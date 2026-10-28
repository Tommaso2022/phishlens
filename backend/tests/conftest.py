"""Applicazione di test: database reale; Redis, email, HIBP e orologio finti."""

from __future__ import annotations

import base64
import secrets

import fakeredis
import pytest
from fastapi.testclient import TestClient
from phishlens_backend.config import Settings
from phishlens_backend.main import create_app
from phishlens_backend.ratelimit import RateLimiter
from phishlens_backend.security.throttle import LoginThrottle
from phishlens_backend.security.totp import SecretBox
from phishlens_backend.services import Services
from phishlens_db.engine import make_engine, make_sessionmaker


def random_key() -> str:
    """Chiave AES-256 nuova a ogni esecuzione: nessuna chiave scritta nel codice."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


TOTP_KEY = random_key()


class Clock:
    """Orologio controllabile per i codici TOTP."""

    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, mail):
        self.sent.append(mail)


class FakeBreach:
    def __init__(self):
        self.breached: set[str] = set()
        self.available = True

    def is_breached(self, password):
        return (password in self.breached) if self.available else None


@pytest.fixture
def settings(database):
    return Settings(
        env="test",
        database_url=database["app"],
        redis_url="redis://non-usato",
        base_url="https://phishlens.test",
        totp_key=TOTP_KEY,
        cookie_secure=True,
    )


@pytest.fixture
def svc(settings, database):
    engine = make_engine(database["app"])
    fake_redis = fakeredis.FakeRedis()
    s = Services(
        settings=settings,
        sessions=make_sessionmaker(engine),
        limiter=RateLimiter(fake_redis),
        mailer=FakeMailer(),
        breach=FakeBreach(),
        throttle=LoginThrottle(fake_redis),
        box=SecretBox(TOTP_KEY),
        clock=Clock(),
    )
    yield s
    engine.dispose()


class CsrfClient(TestClient):
    """Copia il token CSRF dal cookie nell'intestazione, come farà il frontend."""

    def request(self, method, url, **kwargs):
        token = self.cookies.get("__Host-phishlens_csrf")
        if token and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault("X-CSRF-Token", token)
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


@pytest.fixture
def make_client(settings, svc):
    """Crea client indipendenti (per esempio due dispositivi dello stesso utente)."""
    app = create_app(settings, svc)
    clients = []

    def factory():
        # https: i cookie Secure (__Host-) vengono rimandati solo su connessioni cifrate.
        c = CsrfClient(app, base_url="https://testserver")
        clients.append(c)
        return c

    yield factory
    for c in clients:
        c.close()


@pytest.fixture
def client(make_client):
    return make_client()


GOOD_PASSWORD = "cavallo batteria graffetta corretta"


@pytest.fixture
def enroll(svc):
    """Registra, verifica e attiva il TOTP; restituisce (segreto, codici di recupero)."""
    import re

    import pyotp

    def _enroll(c, email, password=GOOD_PASSWORD):
        c.post("/auth/register", json={"email": email, "password": password})
        token = re.search(r"#token=([\w-]+)", svc.mailer.sent[-1].body).group(1)
        assert c.post("/auth/verify-email", json={"token": token}).status_code == 200
        assert c.post("/auth/login", json={"email": email, "password": password}).status_code == 200
        secret = c.post("/auth/totp/setup").json()["secret"]
        r = c.post("/auth/totp/confirm", json={"code": pyotp.TOTP(secret).at(int(svc.clock.now))})
        assert r.status_code == 200
        svc.clock.now += 30
        return secret, r.json()["recovery_codes"]

    return _enroll


@pytest.fixture
def totp_code(svc):
    """Codice TOTP valido all'ora attuale dell'orologio finto; poi avanza di un passo."""
    import pyotp

    def _code(secret):
        code = pyotp.TOTP(secret).at(int(svc.clock.now))
        svc.clock.now += 30
        return code

    return _code


@pytest.fixture
def login_full(totp_code):
    def _login(c, email, secret, password=GOOD_PASSWORD):
        assert c.post("/auth/login", json={"email": email, "password": password}).status_code == 200
        r = c.post("/auth/login/totp", json={"code": totp_code(secret)})
        assert r.status_code == 200

    return _login
