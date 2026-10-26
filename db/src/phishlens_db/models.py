"""Modelli del database di PhishLens.

Scelte di sicurezza (docs/threat-model.md, docs/authentication.md):
- i token di sessione e quelli inviati via email sono salvati solo come hash
  SHA-256: chi legge il database non può usarli (I-03);
- il segreto TOTP è salvato cifrato, con una chiave che non sta nel database;
- i codici di recupero sono salvati con Argon2id, come le password;
- gli identificativi pubblici sono UUID casuali;
- l'email è salvata in minuscolo, con un vincolo che lo garantisce.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class SessionStage(enum.StrEnum):
    PARTIAL = "partial"  # password verificata, manca il secondo fattore
    FULL = "full"


class TokenPurpose(enum.StrEnum):
    VERIFY_EMAIL = "verify_email"
    RESET_PASSWORD = "reset_password"  # noqa: S105  # nosec B105 - nome dello scopo, non una password


class AnalysisStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("daily_quota BETWEEN 0 AND 1000", name="daily_quota_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)  # contro il riuso dei codici
    daily_quota: Mapped[int] = mapped_column(SmallInteger, default=50)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class UserSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    stage: Mapped[SessionStage] = mapped_column(
        Enum(SessionStage, name="session_stage", values_callable=lambda e: [m.value for m in e])
    )
    failed_second_factor: Mapped[int] = mapped_column(SmallInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # scadenza assoluta
    user_agent: Mapped[str | None] = mapped_column(String(200))
    ip_prefix: Mapped[str | None] = mapped_column(String(64))  # IP abbreviato, non completo

    user: Mapped[User] = relationship(back_populates="sessions")


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    __table_args__ = (Index("ix_recovery_codes_user", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(255))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EmailToken(Base):
    __tablename__ = "email_tokens"
    __table_args__ = (Index("ix_email_tokens_user", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    purpose: Mapped[TokenPurpose] = mapped_column(
        Enum(TokenPurpose, name="token_purpose", values_callable=lambda e: [m.value for m in e])
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        Index("ix_analyses_owner_created", "owner_id", "created_at"),
        Index("ix_analyses_expires", "expires_at"),
        CheckConstraint("score IS NULL OR (score >= 0 AND score <= 1)", name="score_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(String(2048))
    host: Mapped[str] = mapped_column(String(253))
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(
            AnalysisStatus, name="analysis_status", values_callable=lambda e: [m.value for m in e]
        ),
        default=AnalysisStatus.QUEUED,
    )
    score: Mapped[float | None] = mapped_column(Float)
    verdict: Mapped[str | None] = mapped_column(String(32))
    explanation: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # retention


class AuditEvent(Base):
    """Registro delle azioni rilevanti. L'utente dell'applicazione può solo
    aggiungere e leggere righe: non può modificarle né cancellarle (R-03)."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_at", "at"), Index("ix_audit_events_user", "user_id"))

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    event: Mapped[str] = mapped_column(String(64))
    ip_prefix: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict | None] = mapped_column(JSONB)
    request_id: Mapped[str | None] = mapped_column(String(64))


# Colonne di testo da non registrare mai nei log (usato dal logging, Fase 3.7).
SENSITIVE_COLUMNS = frozenset({"password_hash", "totp_secret_encrypted", "token_hash", "code_hash"})

__all__ = [
    "Analysis",
    "AnalysisStatus",
    "AuditEvent",
    "Base",
    "EmailToken",
    "RecoveryCode",
    "SENSITIVE_COLUMNS",
    "SessionStage",
    "TokenPurpose",
    "User",
    "UserSession",
]
