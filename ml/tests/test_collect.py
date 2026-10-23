"""Test del raccoglitore con un server finto: nessuna connessione reale.

I domini sono inventati: nessuna richiesta lascia il processo.
"""

import io
import json
import urllib.error
from urllib.parse import urlsplit

import pytest
from phishlens_ml import collect

FEED = "\n".join(
    [
        "https://accesso-banca-verifica-prova.it/login",
        "https://progetto.pages.dev/poste",  # piattaforma condivisa
        "javascript:alert(1)",  # non valido
        "https://conto-sicuro-prova.xyz/x",  # TLD senza server RDAP nel bootstrap finto
        "",
    ]
)
BOOTSTRAP = {
    "services": [[["it"], ["http://insicuro.example/", "https://rdap.example-registry.org/"]]]
}
RDAP_OK = {"events": [{"eventAction": "registration", "eventDate": "2026-10-20T08:00:00Z"}]}


class FakeServer:
    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def __call__(self, req, timeout):
        url = req.full_url
        self.requested.append(url)
        status, body = self.routes.get(url, (404, b""))
        if status != 200:
            raise urllib.error.HTTPError(url, status, "errore", {}, None)
        return io.BytesIO(body)


@pytest.fixture
def server():
    return FakeServer(
        {
            collect.FEED_URL: (200, FEED.encode()),
            collect.BOOTSTRAP_URL: (200, json.dumps(BOOTSTRAP).encode()),
            "https://rdap.example-registry.org/domain/accesso-banca-verifica-prova.it": (
                200,
                json.dumps(RDAP_OK).encode(),
            ),
        }
    )


def make_http(server):
    hosts = {urlsplit(collect.FEED_URL).hostname, urlsplit(collect.BOOTSTRAP_URL).hostname}
    return collect.Http(hosts, opener=server)


def run(tmp_path, server, *extra):
    pauses = []
    code = collect.main(
        ["--out-dir", str(tmp_path), *extra], http=make_http(server), sleep=pauses.append
    )
    return code, pauses


def test_collects_new_urls_once(tmp_path, server):
    assert run(tmp_path, server, "--no-rdap")[0] == 0
    assert run(tmp_path, server, "--no-rdap")[0] == 0
    rows = collect.read_jsonl(tmp_path / "openphish.jsonl")
    assert len(rows) == 3  # il javascript: è scartato, nessun duplicato
    shared = {r["host"]: r["shared_platform"] for r in rows}
    assert shared["progetto.pages.dev"] is True
    assert shared["accesso-banca-verifica-prova.it"] is False


def test_rdap_registration_date_and_statuses(tmp_path, server):
    code, pauses = run(tmp_path, server)
    assert code == 0
    cache = json.loads((tmp_path / "rdap.json").read_text())
    assert cache["accesso-banca-verifica-prova.it"]["registration"] == "2026-10-20T08:00:00Z"
    assert cache["conto-sicuro-prova.xyz"]["status"] == "no_rdap"
    assert len(pauses) == 1  # una pausa dopo ogni richiesta RDAP


def test_never_contacts_phishing_hosts(tmp_path, server):
    run(tmp_path, server)
    collected = {r["host"] for r in collect.read_jsonl(tmp_path / "openphish.jsonl")}
    contacted = {urlsplit(u).hostname for u in server.requested}
    assert not collected & contacted
    http = make_http(server)
    with pytest.raises(collect.CollectError):
        http.get("https://accesso-banca-verifica-prova.it/login", 1000)


def test_only_https_rdap_servers(tmp_path, server):
    run(tmp_path, server)
    assert not [u for u in server.requested if u.startswith("http://")]


def test_errors_are_retried_next_run(tmp_path, server):
    url = "https://rdap.example-registry.org/domain/accesso-banca-verifica-prova.it"
    ok = server.routes.pop(url)
    server.routes[url] = (503, b"")
    run(tmp_path, server)
    cache = json.loads((tmp_path / "rdap.json").read_text())
    assert cache["accesso-banca-verifica-prova.it"]["status"] == "error"
    server.routes[url] = ok
    run(tmp_path, server)
    cache = json.loads((tmp_path / "rdap.json").read_text())
    assert cache["accesso-banca-verifica-prova.it"]["status"] == "ok"


def test_response_size_limit(server):
    server.routes[collect.FEED_URL] = (200, b"x" * 2000)
    with pytest.raises(collect.CollectError):
        make_http(server).get(collect.FEED_URL, max_bytes=1000)


def test_invalid_registration_date_is_ignored():
    rdap = {"events": [{"eventAction": "registration", "eventDate": "<script>"}]}
    assert collect.registration_date(rdap) is None


def test_redirects_are_not_followed():
    """Un redirect verso un altro host deve fallire, non essere seguito."""
    import http.server
    import threading

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://bersaglio-interno.invalid/")
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    req = collect.urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/")
    with pytest.raises(urllib.error.HTTPError) as err:
        collect._default_open(req, timeout=5)
    assert err.value.code == 302
    srv.server_close()
