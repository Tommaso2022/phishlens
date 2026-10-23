"""Raccolta periodica del phishing attivo da OpenPhish, con l'età dei domini.

Uso, dalla radice del repository (pensato per girare ogni 12 ore):
    uv run python -m phishlens_ml.collect

Ogni esecuzione:
 1. scarica l'OpenPhish Community Feed (uso non commerciale, vedi i termini
    su openphish.com) e aggiunge gli URL nuovi a ml/data/collected/openphish.jsonl,
    con la data in cui li ha visti per la prima volta;
 2. per i domini registrati nuovi chiede la data di registrazione ai server RDAP
    ufficiali dei registri, trovati tramite l'elenco pubblicato da IANA.

Regola di sicurezza: il raccoglitore non contatta MAI i siti di phishing, nemmeno
per risolverne il nome. Può collegarsi solo al feed, a IANA e ai server RDAP:
ogni altra destinazione viene rifiutata (vedi Http.get).
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit

from phishlens_core.features import is_shared_platform, registered_domain
from phishlens_core.url import InvalidURL, parse_url

from phishlens_ml.datasets import DATA_DIR

FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
OUT_DIR = DATA_DIR / "collected"
MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_RDAP_BYTES = 1024 * 1024
BOOTSTRAP_MAX_AGE = timedelta(days=7)
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


class CollectError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Rifiuta i redirect: un server consentito non può mandarci verso altri host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib trasforma la risposta 3xx in un HTTPError


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_open(req: urllib.request.Request, timeout: int):
    return _OPENER.open(req, timeout=timeout)


class Http:
    """Client HTTPS che si collega solo agli host esplicitamente consentiti."""

    def __init__(self, allowed_hosts: set[str], opener: Callable | None = None):
        self.allowed = set(allowed_hosts)
        self._open = opener or _default_open

    def allow(self, url: str) -> None:
        self.allowed.add(urlsplit(url).hostname or "")

    def get(self, url: str, max_bytes: int, timeout: int = 30) -> bytes | None:
        """Contenuto della risposta; None se la risorsa non esiste (404)."""
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in self.allowed:
            raise CollectError(f"Destinazione non consentita: {parts.hostname}")
        # Schema e host verificati qui sopra: solo https verso host consentiti.
        req = urllib.request.Request(  # noqa: S310
            url, headers={"Accept": "application/rdap+json, */*"}
        )
        try:
            with self._open(req, timeout) as r:
                data = r.read(max_bytes + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise CollectError(f"HTTP {e.code} da {parts.hostname}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise CollectError(f"Errore di rete verso {parts.hostname}: {e}") from e
        if len(data) > max_bytes:
            raise CollectError(f"Risposta oltre {max_bytes} byte da {parts.hostname}")
        return data


# ------------------------------------------------------------------ feed


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def collect_feed(http: Http, out: Path) -> list[dict]:
    raw = http.get(FEED_URL, MAX_FEED_BYTES)
    if raw is None:
        raise CollectError("Feed non trovato")
    seen = {r["url"] for r in read_jsonl(out)}
    stamp, new = now_iso(), []
    for line in raw.decode("utf-8", "replace").splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        try:
            host = parse_url(url).site_host
        except InvalidURL:
            continue
        seen.add(url)
        new.append(
            {
                "url": url,
                "host": host,
                "registered_domain": registered_domain(host),
                "shared_platform": is_shared_platform(host),
                "first_seen": stamp,
            }
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        for r in new:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return new


# ------------------------------------------------------------------ RDAP


def load_bootstrap(http: Http, path: Path) -> dict[str, str]:
    """Mappa suffisso -> URL base del server RDAP, dall'elenco ufficiale IANA."""
    fresh = path.exists() and (
        datetime.now(UTC) - datetime.fromtimestamp(path.stat().st_mtime, UTC) < BOOTSTRAP_MAX_AGE
    )
    if not fresh:
        data = http.get(BOOTSTRAP_URL, MAX_RDAP_BYTES)
        if data is None:
            raise CollectError("Elenco RDAP di IANA non trovato")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    services = json.loads(path.read_text(encoding="utf-8"))["services"]
    table = {}
    for tlds, urls in services:
        https = [u for u in urls if u.startswith("https://")]
        if https:
            for tld in tlds:
                table[tld.lower()] = https[0].rstrip("/") + "/"
    return table


def registration_date(rdap: dict) -> str | None:
    for event in rdap.get("events", []):
        date = event.get("eventDate")
        if event.get("eventAction") == "registration" and isinstance(date, str):
            return date if ISO_DATE.match(date) else None
    return None


def lookup_domains(
    http: Http,
    domains: list[str],
    bootstrap: dict[str, str],
    cache: dict,
    max_lookups: int,
    pause: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Interroga RDAP per i domini non ancora in cache (o in errore). Rispetta i server
    con una pausa tra le richieste e un massimo per esecuzione."""
    done = 0
    for domain in domains:
        if done >= max_lookups:
            break
        if cache.get(domain, {}).get("status") in {"ok", "not_found", "no_rdap"}:
            continue
        tld = domain.rsplit(".", 1)[-1].lower()  # i server RDAP sono assegnati per TLD
        base = bootstrap.get(tld)
        if base is None:
            cache[domain] = {"status": "no_rdap", "checked": now_iso()}
            continue
        http.allow(base)
        try:
            data = http.get(base + "domain/" + quote(domain), MAX_RDAP_BYTES)
            if data is None:
                cache[domain] = {"status": "not_found", "checked": now_iso()}
            else:
                reg = registration_date(json.loads(data))
                cache[domain] = {"status": "ok", "registration": reg, "checked": now_iso()}
        except (CollectError, ValueError) as e:
            cache[domain] = {"status": "error", "detail": str(e)[:200], "checked": now_iso()}
        done += 1
        sleep(pause)
    return done


def main(
    argv: list[str] | None = None,
    http: Http | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    parser.add_argument("--max-rdap", type=int, default=200, help="richieste RDAP per esecuzione")
    parser.add_argument("--no-rdap", action="store_true")
    args = parser.parse_args(argv)

    http = http or Http({urlsplit(FEED_URL).hostname, urlsplit(BOOTSTRAP_URL).hostname})
    feed_path = args.out_dir / "openphish.jsonl"
    cache_path = args.out_dir / "rdap.json"
    print(f"[{now_iso()}] raccolta OpenPhish")
    try:
        new = collect_feed(http, feed_path)
        useful = [r for r in new if not r["shared_platform"]]
        print(f"  URL nuovi: {len(new)} (su piattaforme condivise: {len(new) - len(useful)})")
        if args.no_rdap:
            return 0
        bootstrap = load_bootstrap(http, args.out_dir / "iana-rdap-bootstrap.json")
        cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
        pending = sorted(
            {r["registered_domain"] for r in read_jsonl(feed_path) if not r["shared_platform"]}
        )
        n = lookup_domains(http, pending, bootstrap, cache, args.max_rdap, sleep=sleep)
        cache_path.write_text(json.dumps(cache, indent=1, ensure_ascii=False) + "\n")
        status = {}
        for v in cache.values():
            status[v["status"]] = status.get(v["status"], 0) + 1
        print(f"  richieste RDAP: {n}; stato dei domini: {status}")
    except CollectError as e:
        print(f"  ERRORE: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
