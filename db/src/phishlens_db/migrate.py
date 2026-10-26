"""Applica le migrazioni del database. Usato dal servizio "migrate" di Docker Compose.

    python -m phishlens_db.migrate

Richiede PHISHLENS_MIGRATION_DATABASE_URL, con le credenziali del proprietario
dello schema: è l'unico processo che le riceve. Il backend e il worker usano
l'utente applicativo, che non può modificare le tabelle.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).parent / "migrations"


def config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    return cfg


def main() -> None:
    command.upgrade(config(), "head")


if __name__ == "__main__":
    main()
