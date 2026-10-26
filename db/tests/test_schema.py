"""Lo schema e i privilegi corrispondono al threat model (T-03, I-04, R-03, D-03)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from phishlens_db.engine import make_engine
from phishlens_db.models import Analysis, AuditEvent, SessionStage, User, UserSession
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

TABLES = {"users", "sessions", "recovery_codes", "email_tokens", "analyses", "audit_events"}


def new_user(s: Session, email: str | None = None) -> User:
    u = User(email=email or f"utente-{uuid.uuid4().hex[:8]}@example.com", password_hash="x")
    s.add(u)
    s.flush()
    return u


def test_migration_creates_all_tables(database):
    names = set(inspect(create_engine(database["owner"])).get_table_names())
    assert names >= TABLES


def test_app_can_read_and_write(app_engine):
    with Session(app_engine) as s, s.begin():
        u = new_user(s)
        s.add(
            Analysis(
                owner_id=u.id,
                url="https://example.com/",
                host="example.com",
                expires_at=datetime.now(UTC) + timedelta(days=30),
            )
        )


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE TABLE intrusa (id int)",
        "DROP TABLE users",
        "ALTER TABLE users ADD COLUMN ruolo text",
        "TRUNCATE users CASCADE",
    ],
)
def test_app_cannot_change_schema(app_engine, statement):
    with pytest.raises(DBAPIError), app_engine.begin() as c:
        c.execute(text(statement))


def test_audit_log_is_append_only_for_app(app_engine):
    with Session(app_engine) as s, s.begin():
        s.add(AuditEvent(event="prova"))
    for statement in ("UPDATE audit_events SET event = 'alterato'", "DELETE FROM audit_events"):
        with pytest.raises(DBAPIError), app_engine.begin() as c:
            c.execute(text(statement))


def test_deleting_user_removes_data_but_keeps_audit(app_engine):
    with Session(app_engine) as s, s.begin():
        u = new_user(s)
        s.add(
            UserSession(
                token_hash=uuid.uuid4().bytes * 2,
                user_id=u.id,
                stage=SessionStage.FULL,
                expires_at=datetime.now(UTC) + timedelta(hours=12),
            )
        )
        s.add(AuditEvent(user_id=u.id, event="login_ok"))
        user_id = u.id
    with Session(app_engine) as s, s.begin():
        s.delete(s.get(User, user_id))
    with app_engine.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM sessions WHERE user_id = :u"), {"u": user_id}
            ).scalar()
            == 0
        )
        orphan = c.execute(
            text("SELECT count(*) FROM audit_events WHERE event = 'login_ok' AND user_id IS NULL")
        ).scalar()
        assert orphan >= 1  # l'evento resta, ma non è più collegato alla persona


def test_email_must_be_lowercase_and_unique(app_engine):
    with pytest.raises(IntegrityError), Session(app_engine) as s, s.begin():
        new_user(s, "Maiuscole@Example.com")
    with Session(app_engine) as s, s.begin():
        new_user(s, "unica@example.com")
    with pytest.raises(IntegrityError), Session(app_engine) as s, s.begin():
        new_user(s, "unica@example.com")


def test_score_must_be_a_probability(app_engine):
    def insert_invalid_score():
        with Session(app_engine) as s, s.begin():
            u = new_user(s)
            s.add(
                Analysis(
                    owner_id=u.id,
                    url="https://e.com/",
                    host="e.com",
                    score=7.0,
                    expires_at=datetime.now(UTC),
                )
            )

    with pytest.raises(IntegrityError):
        insert_invalid_score()


def test_statement_timeout(database):
    engine = make_engine(database["app"], statement_timeout_ms=200)
    with pytest.raises(DBAPIError, match="statement timeout"), engine.connect() as c:
        c.execute(text("SELECT pg_sleep(2)"))
    engine.dispose()


def test_migration_downgrade_and_upgrade(database, alembic_for):
    cfg = alembic_for(database["owner"])
    command.downgrade(cfg, "base")
    assert not set(inspect(create_engine(database["owner"])).get_table_names()) & TABLES
    command.upgrade(cfg, "head")
    assert set(inspect(create_engine(database["owner"])).get_table_names()) >= TABLES
