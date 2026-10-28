"""CSRF, sessioni attive, cambio password e codici di recupero
(ASVS V3, 7.1.x, 7.4.3, 7.5.1, 7.5.2, 8.2.2; threat model T-01, I-02, AC11)."""

from datetime import UTC, datetime, timedelta

from phishlens_db.models import User, UserSession
from sqlalchemy import select

GOOD = "cavallo batteria graffetta corretta"
NEW = "una nuova frase segreta piuttosto lunga"


# ------------------------------------------------------------------ CSRF


def test_csrf_token_required_with_session(client, enroll):
    enroll(client, "csrf@example.com")
    assert client.post("/auth/logout", headers={"X-CSRF-Token": ""}).status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": "a" * 64}).status_code == 403
    assert client.get("/me").status_code == 200  # la sessione è ancora valida
    assert client.post("/auth/logout").status_code == 200  # con il token giusto


def test_foreign_origin_rejected_even_without_session(client):
    body = {"email": "x@example.com", "password": GOOD}
    r = client.post("/auth/login", json=body, headers={"Origin": "https://sito-malevolo.example"})
    assert r.status_code == 403  # login CSRF
    r = client.post("/auth/login", json=body, headers={"Origin": "https://phishlens.test"})
    assert r.status_code == 401  # stessa origine: la richiesta arriva al controllo password


def test_csrf_cookie_flags(client, enroll):
    enroll(client, "cookie-csrf@example.com")
    client.post("/auth/logout")
    r = client.post("/auth/login", json={"email": "cookie-csrf@example.com", "password": GOOD})
    csrf = [c for c in r.headers.get_list("set-cookie") if "phishlens_csrf" in c][0].lower()
    assert "httponly" not in csrf  # il frontend deve poterlo leggere
    assert "samesite=strict" in csrf
    assert "secure" in csrf


# ------------------------------------------------------- durata della sessione


def _partial_ttl(svc, email) -> timedelta:
    with svc.sessions() as db:
        user = db.scalar(select(User).where(User.email == email))
        s = db.scalar(
            select(UserSession)
            .where(UserSession.user_id == user.id)
            .order_by(UserSession.created_at.desc())
        )
        return s.expires_at - s.created_at


def test_enrollment_gets_15_minutes_normal_login_5(client, svc, enroll):
    client.post("/auth/register", json={"email": "durata@example.com", "password": GOOD})
    import re

    token = re.search(r"#token=([\w-]+)", svc.mailer.sent[-1].body).group(1)
    client.post("/auth/verify-email", json={"token": token})
    client.post("/auth/login", json={"email": "durata@example.com", "password": GOOD})
    assert timedelta(minutes=14) < _partial_ttl(svc, "durata@example.com") <= timedelta(minutes=15)

    other = enroll(client, "durata2@example.com")
    assert other
    client.post("/auth/logout")
    client.post("/auth/login", json={"email": "durata2@example.com", "password": GOOD})
    assert _partial_ttl(svc, "durata2@example.com") <= timedelta(minutes=5)


# ---------------------------------------------------------- sessioni attive


def test_list_and_revoke_other_device(make_client, enroll, login_full):
    laptop, phone = make_client(), make_client()
    secret, _ = enroll(laptop, "due@example.com")
    login_full(phone, "due@example.com", secret)

    sessions = laptop.get("/me/sessions").json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])

    bad = laptop.post(f"/me/sessions/{other['id']}/revoke", json={"password": "sbagliata!!"})
    assert bad.status_code == 401
    ok = laptop.post(f"/me/sessions/{other['id']}/revoke", json={"password": GOOD})
    assert ok.status_code == 200
    assert phone.get("/me").status_code == 401  # il telefono è stato disconnesso
    assert laptop.get("/me").status_code == 200


def test_cannot_revoke_someone_elses_session(make_client, enroll):
    alice, bob = make_client(), make_client()
    enroll(alice, "alice@example.com")
    enroll(bob, "bob@example.com")
    alice_session = alice.get("/me/sessions").json()[0]["id"]
    r = bob.post(f"/me/sessions/{alice_session}/revoke", json={"password": GOOD})
    assert r.status_code == 404  # come se non esistesse (IDOR, AC11)
    assert alice.get("/me").status_code == 200


def test_revoke_others(make_client, enroll, login_full):
    a, b, c = make_client(), make_client(), make_client()
    secret, _ = enroll(a, "tre@example.com")
    login_full(b, "tre@example.com", secret)
    login_full(c, "tre@example.com", secret)
    r = a.post("/me/sessions/revoke-others", json={"password": GOOD})
    assert r.json()["detail"] == "Sessioni chiuse: 2."
    assert b.get("/me").status_code == c.get("/me").status_code == 401
    assert a.get("/me").status_code == 200


def test_at_most_five_full_sessions(make_client, enroll, login_full):
    first = make_client()
    secret, _ = enroll(first, "cinque-sessioni@example.com")
    others = [make_client() for _ in range(5)]
    for c in others:
        login_full(c, "cinque-sessioni@example.com", secret)
    assert first.get("/me").status_code == 401  # la meno recente è stata chiusa
    assert all(c.get("/me").status_code == 200 for c in others)


# ------------------------------------------------------------ cambio password


def test_change_password_requires_password_and_totp(
    make_client, svc, enroll, login_full, totp_code
):
    me, other = make_client(), make_client()
    secret, _ = enroll(me, "cambio@example.com")
    login_full(other, "cambio@example.com", secret)

    body = {"current_password": GOOD, "new_password": NEW, "totp_code": "000000"}
    assert me.post("/me/password", json=body).status_code == 401
    body["totp_code"] = totp_code(secret)
    body["current_password"] = "password attuale sbagliata"
    assert me.post("/me/password", json=body).status_code == 401
    body.update(current_password=GOOD, totp_code=totp_code(secret))
    r = me.post("/me/password", json=body)
    assert r.status_code == 200

    assert other.get("/me").status_code == 401  # altre sessioni chiuse
    assert me.get("/me").status_code == 200
    assert "password è stata cambiata" in svc.mailer.sent[-1].subject
    fresh = make_client()
    old = fresh.post("/auth/login", json={"email": "cambio@example.com", "password": GOOD})
    assert old.status_code == 401
    new = fresh.post("/auth/login", json={"email": "cambio@example.com", "password": NEW})
    assert new.status_code == 200


def test_new_password_must_respect_policy(client, enroll, totp_code):
    secret, _ = enroll(client, "policy@example.com")
    body = {"current_password": GOOD, "new_password": "corta", "totp_code": totp_code(secret)}
    assert client.post("/me/password", json=body).status_code == 422
    body.update(new_password=GOOD, totp_code=totp_code(secret))
    assert client.post("/me/password", json=body).status_code == 422  # uguale all'attuale


# ------------------------------------------------------- codici di recupero


def test_regenerate_recovery_codes_invalidates_old(client, enroll, totp_code):
    secret, old_codes = enroll(client, "nuovicodici@example.com")
    r = client.post("/me/recovery-codes", json={"password": GOOD, "totp_code": totp_code(secret)})
    assert r.status_code == 200
    new_codes = r.json()["recovery_codes"]
    assert set(new_codes).isdisjoint(old_codes)

    client.post("/auth/logout")
    client.post("/auth/login", json={"email": "nuovicodici@example.com", "password": GOOD})
    assert client.post("/auth/login/recovery", json={"code": old_codes[0]}).status_code == 401
    assert client.post("/auth/login/recovery", json={"code": new_codes[0]}).status_code == 200


def test_sensitive_operations_need_full_session(client, svc):
    client.post("/auth/register", json={"email": "parziale@example.com", "password": GOOD})
    import re

    token = re.search(r"#token=([\w-]+)", svc.mailer.sent[-1].body).group(1)
    client.post("/auth/verify-email", json={"token": token})
    client.post("/auth/login", json={"email": "parziale@example.com", "password": GOOD})
    assert client.get("/me/sessions").status_code == 401
    r = client.post("/me/recovery-codes", json={"password": GOOD, "totp_code": "123456"})
    assert r.status_code == 401


def test_session_records_reduced_ip(client, svc, enroll):
    enroll(client, "ip@example.com")
    s = client.get("/me/sessions").json()[0]
    assert s["ip_prefix"] in (None, "sconosciuto") or s["ip_prefix"].endswith(("/24", "/48"))
    assert datetime.fromisoformat(s["created_at"]) <= datetime.now(UTC) + timedelta(seconds=5)
