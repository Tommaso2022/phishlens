"""Ambiente delle migrazioni Alembic."""

import os
from logging.config import fileConfig

from alembic import context
from phishlens_db.models import Base
from sqlalchemy import create_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    url = os.environ.get("PHISHLENS_MIGRATION_DATABASE_URL")
    if not url:
        raise SystemExit(
            "Imposta PHISHLENS_MIGRATION_DATABASE_URL (utente proprietario dello schema)."
        )
    return url


def run_migrations_offline() -> None:
    context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
