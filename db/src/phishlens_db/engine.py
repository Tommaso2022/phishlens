"""Connessione al database."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker


def make_engine(url: str, *, pool_size: int = 5, statement_timeout_ms: int = 5000) -> Engine:
    """Engine con limiti espliciti: pool piccolo e timeout sulle query (threat model D-03)."""
    return create_engine(
        url,
        pool_size=pool_size,
        max_overflow=0,
        pool_pre_ping=True,
        connect_args={"options": f"-c statement_timeout={statement_timeout_ms}"},
    )


def make_sessionmaker(engine: Engine) -> sessionmaker:
    return sessionmaker(engine, expire_on_commit=False)
