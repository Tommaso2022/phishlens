"""Applicazione di test: database reale, Redis finto, email e HIBP finti."""

from __future__ import annotations

import fakeredis
import pytest
from fastapi.testclient import TestClient
from phishlens_backend.config import Settings
from phishlens_backend.main import create_app
from phishlens_backend.ratelimit import RateLimiter
from phishlens_backend.services import Services
from phishlens_db.engine import make_engine, make_sessionmaker


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
    )


@pytest.fixture
def svc(settings, database):
    engine = make_engine(database["app"])
    s = Services(
        settings=settings,
        sessions=make_sessionmaker(engine),
        limiter=RateLimiter(fakeredis.FakeRedis()),
        mailer=FakeMailer(),
        breach=FakeBreach(),
    )
    yield s
    engine.dispose()


@pytest.fixture
def client(settings, svc):
    with TestClient(create_app(settings, svc)) as c:
        yield c
