"""Servizi condivisi dall'applicazione. Nei test si sostituiscono con versioni finte."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

import redis
from fastapi import Depends, Request
from phishlens_db.engine import make_engine, make_sessionmaker
from sqlalchemy.orm import Session, sessionmaker

from phishlens_backend.config import Settings
from phishlens_backend.mailer import Mailer, SmtpMailer
from phishlens_backend.ratelimit import RateLimiter
from phishlens_backend.security.breach import BreachChecker, DisabledBreachChecker


@dataclass
class Services:
    settings: Settings
    sessions: sessionmaker
    limiter: RateLimiter
    mailer: Mailer
    breach: BreachChecker | DisabledBreachChecker

    @classmethod
    def from_settings(cls, settings: Settings) -> Services:
        engine = make_engine(settings.database_url.get_secret_value())
        client = redis.Redis.from_url(settings.redis_url.get_secret_value(), socket_timeout=2)
        return cls(
            settings=settings,
            sessions=make_sessionmaker(engine),
            limiter=RateLimiter(client),
            mailer=SmtpMailer(settings.smtp_host, settings.smtp_port, settings.mail_from),
            breach=BreachChecker() if settings.hibp_enabled else DisabledBreachChecker(),
        )


def services(request: Request) -> Services:
    return request.app.state.services


def db_session(request: Request) -> Iterator[Session]:
    """Una transazione per richiesta: confermata se tutto va bene, annullata altrimenti."""
    with request.app.state.services.sessions() as session, session.begin():
        yield session


# Tipi da usare nelle funzioni delle route: `db: DbSession`, `svc: Svc`.
DbSession = Annotated[Session, Depends(db_session)]
Svc = Annotated[Services, Depends(services)]
