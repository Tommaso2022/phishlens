"""Registrazione e verifica dell'email (ASVS V6.2, 6.4.1, 2.3.4; threat model AC1, T-11)."""

import logging
import re
from datetime import UTC, datetime, timedelta

from phishlens_db.models import AuditEvent, EmailToken, User
from sqlalchemy import select, text, update

GOOD = "cavallo batteria graffetta corretta"


def register(client, email, password=GOOD, **extra):
    return client.post("/auth/register", json={"email": email, "password": password, **extra})


def token_from(mail) -> str:
    return re.search(r"#token=([A-Za-z0-9_-]+)", mail.body).group(1)


def test_register_new_user_sends_verification(client, svc):
    r = register(client, "Nuovo.Utente@Example.com")
    assert r.status_code == 202
    assert svc.mailer.sent[-1].to == "nuovo.utente@example.com"
    token = token_from(svc.mailer.sent[-1])
    with svc.sessions() as db:
        user = db.scalar(select(User).where(User.email == "nuovo.utente@example.com"))
        assert user.email_verified_at is None
        assert user.password_hash.startswith("$argon2id$")
        stored = db.scalars(
            select(EmailToken.token_hash).where(EmailToken.user_id == user.id)
        ).all()
        assert token.encode() not in stored  # nel database c'è solo l'hash


def test_same_reply_for_new_and_existing_address(client, svc):
    first = register(client, "doppio@example.com")
    second = register(client, "doppio@example.com")
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()  # nessuna enumerazione degli account


def test_existing_verified_address_gets_notice_not_token(client, svc):
    register(client, "verificato@example.com")
    assert (
        client.post(
            "/auth/verify-email", json={"token": token_from(svc.mailer.sent[-1])}
        ).status_code
        == 200
    )
    register(client, "verificato@example.com")
    assert "Tentativo di registrazione" in svc.mailer.sent[-1].subject
    assert "#token=" not in svc.mailer.sent[-1].body


def test_weak_and_breached_passwords_rejected(client, svc):
    assert register(client, "debole@example.com", "corta").status_code == 422
    svc.breach.breached.add("cavalli nel prato verde 2019")
    r = register(client, "violata@example.com", "cavalli nel prato verde 2019")
    assert r.status_code == 422
    assert "violazioni" in str(r.json())


def test_hibp_unavailable_does_not_block(client, svc):
    svc.breach.available = False
    assert register(client, "senzahibp@example.com").status_code == 202
    with svc.sessions() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.event == "registrazione")
            .order_by(AuditEvent.id.desc())
        )
        assert event.details == {"hibp": "non disponibile"}


def test_password_never_echoed_in_errors(client):
    secret = "segreto-da-non-ripetere-mai"
    r = client.post("/auth/register", json={"email": "non-una-email", "password": secret})
    assert r.status_code == 422
    assert secret not in r.text
    r = client.post(
        "/auth/register", json={"email": "x@example.com", "password": secret, "is_active": False}
    )
    assert r.status_code == 422  # campi sconosciuti rifiutati (mass assignment)
    assert secret not in r.text


def test_registration_rate_limit_per_ip(client, svc):
    codes = [register(client, f"limite{i}@example.com").status_code for i in range(6)]
    assert codes[:5] == [202] * 5
    assert codes[5] == 429


def test_verification_token_single_use(client, svc):
    register(client, "unavolta@example.com")
    token = token_from(svc.mailer.sent[-1])
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_new_verification_invalidates_previous(client, svc):
    register(client, "rinvio@example.com")
    old = token_from(svc.mailer.sent[-1])
    register(client, "rinvio@example.com")
    new = token_from(svc.mailer.sent[-1])
    assert client.post("/auth/verify-email", json={"token": old}).status_code == 400
    assert client.post("/auth/verify-email", json={"token": new}).status_code == 200


def test_expired_token_rejected(client, svc):
    register(client, "scaduto@example.com")
    token = token_from(svc.mailer.sent[-1])
    with svc.sessions() as db, db.begin():
        db.execute(update(EmailToken).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_invalid_token_format_rejected(client):
    assert client.post("/auth/verify-email", json={"token": "<script>"}).status_code == 422


def test_tokens_and_passwords_not_logged(client, svc, caplog):
    caplog.set_level(logging.DEBUG)
    register(client, "log@example.com")
    token = token_from(svc.mailer.sent[-1])
    client.post("/auth/verify-email", json={"token": token})
    assert token not in caplog.text
    assert GOOD not in caplog.text


def test_audit_events_written(client, svc):
    register(client, "audit@example.com")
    with svc.sessions() as db:
        n = db.execute(
            text("SELECT count(*) FROM audit_events WHERE event = 'registrazione'")
        ).scalar()
        assert n >= 1
