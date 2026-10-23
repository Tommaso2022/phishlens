import socket

import pytest
from phishlens_core.features import (
    FEATURE_NAMES,
    extract_host_features,
    is_shared_platform,
    registered_domain,
    shannon_entropy,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """L'estrazione delle feature non deve mai usare la rete."""

    def blocked(*args, **kwargs):
        raise AssertionError("tentativo di connessione di rete")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def test_all_features_present():
    assert set(extract_host_features("example.com")) == set(FEATURE_NAMES)


def test_www_does_not_change_features():
    assert extract_host_features("www.example.com") == extract_host_features("example.com")


def test_brand_in_subdomain():
    f = extract_host_features("paypal.login-verifica.xyz")
    assert f["brand_in_subdomain"] == 1
    assert f["n_keywords"] >= 1
    assert f["suffix"] == "xyz"


def test_official_brand_domain_is_not_flagged():
    f = extract_host_features("paypal.com")
    assert f["brand_in_domain_not_exact"] == 0
    assert f["brand_in_subdomain"] == 0


def test_brand_inside_other_domain():
    assert extract_host_features("paypal-sicurezza.com")["brand_in_domain_not_exact"] == 1


def test_ip_and_punycode():
    assert extract_host_features("192.168.1.10")["is_ip"] == 1
    assert extract_host_features("192.168.1.10")["suffix"] == "(ip)"
    assert extract_host_features("xn--bcher-kva.example")["is_punycode"] == 1


def test_registered_domain():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("utente.github.io") == "utente.github.io"


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == 1


def test_italian_keywords():
    assert extract_host_features("paypal-sicurezza.com")["n_keywords"] == 1
    assert extract_host_features("poste.it-verifica-account.xyz")["n_keywords"] == 2


def test_character_features_use_unicode_form():
    # "аррӏе.рф": "apple" scritto con lettere cirilliche (attacco omografico).
    f = extract_host_features("xn--80ak6aa92e.xn--p1ai")
    assert f["n_digits"] == 0
    assert f["n_hyphens"] == 0
    assert f["host_length"] == len("аррӏе.рф")
    assert f["is_punycode"] == 1


def test_accented_italian_domain():
    f = extract_host_features("xn--citt-3na.it")  # città.it
    assert f["n_digits"] == 0
    assert f["n_hyphens"] == 0
    assert f["domain_label_length"] == len("città")


@pytest.mark.parametrize(
    ("host", "shared"),
    [
        ("app-utente.web.app", True),
        ("progetto.firebaseapp.com", True),
        ("utente.github.io", True),
        ("qualcosa.ipfs.io", True),
        ("www.unife.it", False),
        ("paypal-sicurezza.com", False),
    ],
)
def test_shared_platforms(host, shared):
    assert is_shared_platform(host) is shared
