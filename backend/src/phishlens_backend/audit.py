"""Registrazione degli eventi di audit. Mai password, token o hash nei dettagli."""

from __future__ import annotations

import uuid

from phishlens_db.models import AuditEvent
from sqlalchemy.orm import Session


def record(
    db: Session,
    event: str,
    *,
    user_id: uuid.UUID | None = None,
    ip_prefix: str | None = None,
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(event=event, user_id=user_id, ip_prefix=ip_prefix, details=details))
