"""Login in due passi, TOTP, codici di recupero e limiti sui tentativi
(ASVS 6.3.1, 6.3.3, 6.4.3, 6.5.x, 7.2.x; threat model S-01, AC10, T-11)."""

import base64
import re
import secrets
import uuid

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from phishlens_backend.security.totp import SecretBox
from phishlens_db.models import RecoveryCode, User, UserSession
from sqlalchemy import select, text

GOOD = "cavallo batteria graffetta corretta"
COOKIE = "__Host-phishlens_session"


def verified_user(client, svc, email):
    client.post("/auth/register", json={"email": email, "password": GOOD})
    token = re.search(r"#token=([\w-]+)", svc.mailer.sent[-1].body).group(1)
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200


def login(client, email, password=GOOD):
    return client.post("/auth/login", json={"email": email, "password": password})


def code_at(secret, now):
    return pyotp.TOTP(secret).at(int(now))


def enroll(client, svc, email):
    """Utente verificato con TOTP attivo; restituisce (segreto, codici di recupero)."""
    verified_user(client, svc, email)
    assert login(client, email).json() == {"next": "totp_setup"}
    secret = client.post("/auth/totp/setup").json()["secret"]
    r = client.post("/auth/totp/confirm", json={"code": code_at(secret, svc.clock.now)})
    assert r.status_code == 200
    svc.clock.now += 30  # il passo usato per l'attivazione non si può riusare
    return secret, r.json()["recovery_codes"]


def test_full_enrollment_flow_and_cookie_flags(client, svc):
    verified_user(client, svc, "flusso@example.com")
    r = login(client, "flusso@example.com")
    cookie = r.headers["set-cookie"]
    assert COOKIE in cookie
    for flag in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert client.get("/me").status_code == 401  # la sessione parziale non basta

    setup = client.post("/auth/totp/setup").json()
    assert setup["uri"].startswith("otpauth://totp/PhishLens")
    r = client.post("/auth/totp/confirm", json={"code": code_at(setup["secret"], svc.clock.now)})
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10
    assert all(re.fullmatch(r"([A-Z2-7]{4}-){3}[A-Z2-7]{4}", c) for c in codes)
    me = client.get("/me").json()
    assert me["totp_enabled"] is True
    assert me["recovery_codes_left"] == 10


def test_totp_secret_encrypted_and_bound_to_user(client, svc):
    secret, _ = enroll(client, svc, "cifrato@example.com")
    with svc.sessions() as db:
        user = db.scalar(select(User).where(User.email == "cifrato@example.com"))
        assert secret.encode() not in user.totp_secret_encrypted
        assert svc.box.decrypt(user.totp_secret_encrypted, user.id) == secret
        with pytest.raises(InvalidTag):  # copiato su un altro utente non si decifra
            svc.box.decrypt(user.totp_secret_encrypted, uuid.uuid4())
        with pytest.raises(InvalidTag):  # con un'altra chiave nemmeno
            SecretBox(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()).decrypt(
                user.totp_secret_encrypted, user.id
            )


def test_recovery_codes_hashed(client, svc):
    _, codes = enroll(client, svc, "hashati@example.com")
    with svc.sessions() as db:
        hashes = db.scalars(select(RecoveryCode.code_hash)).all()
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert not any(c.replace("-", "") in h for c in codes for h in hashes)


def test_login_with_totp(client, svc):
    secret, _ = enroll(client, svc, "totp@example.com")
    client.post("/auth/logout")
    assert login(client, "totp@example.com").json() == {"next": "totp"}
    r = client.post("/auth/login/totp", json={"code": code_at(secret, svc.clock.now)})
    assert r.status_code == 200
    assert client.get("/me").status_code == 200


def test_previous_step_accepted_older_rejected(client, svc):
    secret, _ = enroll(client, svc, "finestra@example.com")
    svc.clock.now += 120  # lontano dal passo usato per l'attivazione
    client.post("/auth/logout")
    login(client, "finestra@example.com")
    old = code_at(secret, svc.clock.now - 60)  # due passi fa
    assert client.post("/auth/login/totp", json={"code": old}).status_code == 401
    previous = code_at(secret, svc.clock.now - 30)  # passo precedente: tollerato
    assert client.post("/auth/login/totp", json={"code": previous}).status_code == 200


def test_totp_code_cannot_be_reused(client, svc):
    secret, _ = enroll(client, svc, "riuso@example.com")
    code = code_at(secret, svc.clock.now)
    client.post("/auth/logout")
    login(client, "riuso@example.com")
    assert client.post("/auth/login/totp", json={"code": code}).status_code == 200
    client.post("/auth/logout")
    login(client, "riuso@example.com")
    assert client.post("/auth/login/totp", json={"code": code}).status_code == 401


def test_recovery_code_single_use_and_format_tolerant(client, svc):
    _, codes = enroll(client, svc, "recupero@example.com")
    client.post("/auth/logout")
    login(client, "recupero@example.com")
    r = client.post("/auth/login/recovery", json={"code": codes[0].lower().replace("-", " ")})
    assert r.status_code == 200
    assert "rimasti: 9" in r.json()["detail"]
    client.post("/auth/logout")
    login(client, "recupero@example.com")
    assert client.post("/auth/login/recovery", json={"code": codes[0]}).status_code == 401


def test_five_wrong_codes_cancel_partial_session(client, svc):
    enroll(client, svc, "cinque@example.com")
    client.post("/auth/logout")
    login(client, "cinque@example.com")
    for _ in range(5):
        assert client.post("/auth/login/totp", json={"code": "000000"}).status_code == 401
    assert client.post("/auth/login/totp", json={"code": "000000"}).status_code == 401
    with svc.sessions() as db:
        n = db.execute(
            text("SELECT count(*) FROM audit_events WHERE event = 'sessione_parziale_annullata'")
        ).scalar()
    assert n == 1  # l'evento è salvato anche se la risposta è un errore


def test_generic_errors_and_no_enumeration(client, svc):
    verified_user(client, svc, "esiste@example.com")
    wrong = login(client, "esiste@example.com", "password sbagliata ma lunga")
    missing = login(client, "non-esiste@example.com", "password sbagliata ma lunga")
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()


def test_failed_logins_are_audited(client, svc):
    verified_user(client, svc, "audit-login@example.com")
    login(client, "audit-login@example.com", "password sbagliata ma lunga")
    with svc.sessions() as db:
        n = db.execute(
            text("SELECT count(*) FROM audit_events WHERE event = 'login_fallito'")
        ).scalar()
    assert n >= 1


def test_progressive_delay_after_five_failures(client, svc):
    verified_user(client, svc, "lento@example.com")
    codes = [
        login(client, "lento@example.com", "password sbagliata ma lunga").status_code
        for _ in range(6)
    ]
    assert codes[:6] == [401] * 6
    r = login(client, "lento@example.com")  # anche con la password giusta: attendere
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_unverified_email_cannot_log_in(client, svc):
    client.post("/auth/register", json={"email": "nonverificato@example.com", "password": GOOD})
    assert login(client, "nonverificato@example.com").status_code == 403


def test_partial_session_cannot_skip_second_factor(client, svc):
    enroll(client, svc, "salto@example.com")
    client.post("/auth/logout")
    login(client, "salto@example.com")
    assert client.get("/me").status_code == 401
    assert client.post("/auth/totp/setup").status_code == 409  # TOTP già attivo


def test_session_token_rotates_and_is_stored_hashed(client, svc):
    verified_user(client, svc, "rotazione@example.com")
    login(client, "rotazione@example.com")
    partial = client.cookies.get(COOKIE)
    secret = client.post("/auth/totp/setup").json()["secret"]
    client.post("/auth/totp/confirm", json={"code": code_at(secret, svc.clock.now)})
    full = client.cookies.get(COOKIE)
    assert partial != full
    with svc.sessions() as db:
        stored = db.scalars(select(UserSession.token_hash)).all()
    assert full.encode() not in stored


def test_logout_invalidates_server_side(client, svc):
    enroll(client, svc, "uscita@example.com")
    token = client.cookies.get(COOKIE)
    client.post("/auth/logout")
    client.cookies.set(COOKIE, token, domain="testserver")  # cookie rubato prima del logout
    assert client.get("/me").status_code == 401
