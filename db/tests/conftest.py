"""Database di test: ogni sessione di test crea un database nuovo e lo elimina alla fine.

Variabili d'ambiente:
  PHISHLENS_TEST_ADMIN_URL  URL di un utente amministratore dell'istanza di test,
                            per esempio postgresql+psycopg://phishlens:...@127.0.0.1:55432/postgres

Protezione: i test creano ruoli e database, quindi si rifiutano di girare su
un'istanza che non sia dichiarata di test (cluster_name = phishlens-test, impostato
dal servizio db-test di compose.yaml). In CI la variabile
PHISHLENS_TEST_ALLOW_ANY_CLUSTER=1 permette di usare il container dedicato.
"""

from __future__ import annotations

import os
import secrets

import pytest
from alembic import command
from alembic.config import Config
from phishlens_db import migrate
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

OWNER, APP = "phishlens_owner", "phishlens_app"
OWNER_PW, APP_PW = "test-owner-pw", "test-app-pw"  # noqa: S105 - solo per l'istanza di test


def _admin_url():
    url = os.environ.get("PHISHLENS_TEST_ADMIN_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("PHISHLENS_TEST_ADMIN_URL non impostata in CI")
        pytest.skip("Database di test non configurato (PHISHLENS_TEST_ADMIN_URL)")
    return make_url(url)


def _alembic(url: str) -> Config:
    os.environ["PHISHLENS_MIGRATION_DATABASE_URL"] = url
    return migrate.config()


@pytest.fixture(scope="session")
def database():
    admin = _admin_url()
    admin_engine = create_engine(admin, isolation_level="AUTOCOMMIT", pool_pre_ping=True)
    name = f"phishlens_test_{secrets.token_hex(4)}"
    with admin_engine.connect() as c:
        cluster = c.execute(text("SHOW cluster_name")).scalar()
        if cluster != "phishlens-test" and not os.environ.get("PHISHLENS_TEST_ALLOW_ANY_CLUSTER"):
            pytest.fail(f"Istanza '{cluster}' non dichiarata di test: rifiuto di modificarla.")
        for role, pw in ((OWNER, OWNER_PW), (APP, APP_PW)):
            exists = c.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
            ).scalar()
            verb = "ALTER" if exists else "CREATE"
            c.execute(text(f"{verb} ROLE {role} LOGIN PASSWORD '{pw}'"))  # nosec B608 - valori costanti
        c.execute(text(f"CREATE DATABASE {name} OWNER {OWNER}"))

    owner_url = admin.set(username=OWNER, password=OWNER_PW, database=name)
    app_url = admin.set(username=APP, password=APP_PW, database=name)
    owner_str = owner_url.render_as_string(hide_password=False)
    command.upgrade(_alembic(owner_str), "head")
    yield {"owner": owner_str, "app": app_url.render_as_string(hide_password=False)}

    admin_engine.dispose()  # connessione nuova: quella iniziale può essere scaduta
    with admin_engine.connect() as c:
        c.execute(text(f"DROP DATABASE {name} WITH (FORCE)"))
    admin_engine.dispose()


@pytest.fixture
def app_engine(database):
    engine = create_engine(database["app"])
    yield engine
    engine.dispose()
