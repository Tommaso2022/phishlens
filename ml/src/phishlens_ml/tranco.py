"""Download e lettura delle classifiche Tranco (https://tranco-list.eu/).

Due liste: domini registrati, e domini con sottodomini (mail.google.com, ...).
Ogni archivio viene registrato nel manifest con hash e ID permanente della
lista, così si può citare e riprodurre esattamente la versione usata.
"""

from __future__ import annotations

import csv
import io
import urllib.request
import zipfile
from pathlib import Path

from phishlens_ml import datasets as ds

LISTS = {
    "domains": (
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://tranco-list.eu/top-1m-id",
        "tranco-top-1m.zip",
    ),
    "subdomains": (
        "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip",
        "https://tranco-list.eu/top-1m-id?subdomains=true",
        "tranco-top-1m-subdomains.zip",
    ),
}
MAX_BYTES = 50 * 1024 * 1024
MAX_CSV_BYTES = 200 * 1024 * 1024
CITATION = "Le Pochat et al., Tranco: A Research-Oriented Top Sites Ranking (NDSS 2019)"


def fetch(kind: str, data_dir: Path, manifest: dict) -> Path:
    url, id_url, filename = LISTS[kind]
    raw = data_dir / "raw" / filename
    meta = None
    if not raw.exists():
        print(f"Download da {url} ...")
        ds.download(url, raw, max_bytes=MAX_BYTES)
        with urllib.request.urlopen(id_url, timeout=30) as r:  # noqa: S310  # nosec B310
            list_id = r.read(64).decode("ascii", "replace").strip()
        meta = {"url": url, "tranco_list_id": list_id, "citation": CITATION}
    ds.verify_or_record(filename, raw, manifest, meta)
    return raw


def read(raw: Path, top_n: int) -> list[str]:
    """I primi top_n nomi della lista, nell'ordine della classifica."""
    with zipfile.ZipFile(raw) as zf:
        members = [i for i in zf.infolist() if i.filename.endswith(".csv")]
        if len(members) != 1 or members[0].file_size > MAX_CSV_BYTES:
            names = [i.filename for i in zf.infolist()]
            raise ds.DatasetError(f"Archivio Tranco inatteso: {names}")
        text = io.TextIOWrapper(zf.open(members[0]), encoding="utf-8")
        names: list[str] = []
        for row in csv.reader(text):
            if len(row) != 2 or not row[0].isdigit():
                continue  # eventuale intestazione o riga malformata
            if int(row[0]) > top_n:
                break
            names.append(row[1].strip())
    if not names:
        raise ds.DatasetError("Nessun dominio letto dall'elenco Tranco.")
    return names
