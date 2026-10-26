import httpx
import pytest
from phishlens_backend.security import passwords
from phishlens_backend.security.breach import BreachChecker

GOOD = "cavallo batteria graffetta corretta"


def test_hash_is_argon2id_and_verifies_exactly():
    h = passwords.hash_password(GOOD)
    assert h.startswith("$argon2id$")
    assert passwords.verify_password(h, GOOD)
    assert not passwords.verify_password(h, GOOD + " ")  # nessun trim (ASVS 6.2.8)
    assert not passwords.verify_password(h, GOOD.upper())


@pytest.mark.parametrize(
    "pw", [GOOD, "frase senza simboli né numeri", "àèìòù çß ñ 漢字 frase", "x" * 128]
)
def test_any_composition_accepted(pw):
    assert passwords.policy_problems(pw) == []


@pytest.mark.parametrize(
    ("pw", "fragment"),
    [
        ("troppo corta", "almeno 15"),
        ("y" * 129, "al massimo 128"),
        ("PhishLens è il mio servizio", "nome del servizio"),
        ("ph1shl3ns sicurissimo 2026", "nome del servizio"),
    ],
)
def test_policy_rejections(pw, fragment):
    assert any(fragment in p for p in passwords.policy_problems(pw))


def test_email_local_part_rejected():
    assert passwords.policy_problems("mario.rossi è la mia password", "mario.rossi@example.com")


def test_common_password_list_loaded_and_used():
    common = passwords.common_passwords()
    assert len(common) >= 3000  # ASVS 6.2.4
    example = next(iter(common))
    assert any("più usate" in p for p in passwords.policy_problems(example.upper()))


def _hibp(handler):
    return BreachChecker(httpx.Client(transport=httpx.MockTransport(handler)))


def test_hibp_k_anonymity_and_padding():
    seen = {}

    def handler(request):
        seen["url"], seen["padding"] = str(request.url), request.headers.get("Add-Padding")
        # SHA-1 di "password": 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        return httpx.Response(200, text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\nAAAA:0\n")

    assert _hibp(handler).is_breached("password") is True
    assert seen["url"].endswith("/range/5BAA6")  # solo 5 caratteri lasciano il backend
    assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" not in seen["url"]
    assert seen["padding"] == "true"


def test_hibp_padding_rows_are_ignored():
    def handler(request):
        return httpx.Response(200, text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n")

    assert _hibp(handler).is_breached("password") is False


def test_hibp_unavailable_returns_none():
    def handler(request):
        raise httpx.ConnectError("rete assente")

    assert _hibp(handler).is_breached("qualunque") is None
    assert _hibp(lambda r: httpx.Response(503)).is_breached("x") is None
