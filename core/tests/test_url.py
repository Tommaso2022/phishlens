import pytest
from phishlens_core.url import InvalidURL, parse_url


def test_normalizes_host():
    p = parse_url("  HTTPS://WWW.Example.COM./Path?q=1  ")
    assert (p.scheme, p.host, p.path, p.query) == ("https", "www.example.com", "/Path", "q=1")
    assert p.site_host == "example.com"


def test_unicode_host_becomes_punycode():
    assert parse_url("https://bücher.example/").host == "xn--bcher-kva.example"


def test_www_is_not_stripped_from_short_hosts():
    assert parse_url("http://www.com/").site_host == "www.com"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/",
        "https://utente:password@example.com/",
        "https://example.com:8443/",
        "https://example.com:99999/",
        "https:///solo-percorso",
        "https://exa\nmple.com/",
        "https://" + "a" * 2050 + ".com/",
        "",
    ],
)
def test_rejects_invalid_urls(url):
    with pytest.raises(InvalidURL):
        parse_url(url)


def test_parser_differential_userinfo_trick():
    # Un parser ingenuo potrebbe leggere "pubblico.example" come host:
    # rifiutare le credenziali chiude questa strada (threat model E-05).
    with pytest.raises(InvalidURL):
        parse_url("http://pubblico.example@127.0.0.1/")


def test_ip_host():
    assert parse_url("http://192.168.1.10/").is_ip
    assert parse_url("http://[::1]/").host == "::1"
