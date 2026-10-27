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


@pytest.fixture
def client(settings, svc):
    # https: i cookie Secure (__Host-) vengono rimandati solo su connessioni cifrate.
    with TestClient(create_app(settings, svc), base_url="https://testserver") as c:
        yield c
