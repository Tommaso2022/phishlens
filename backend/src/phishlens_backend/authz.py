"""Livello d'accesso di ogni route: un solo elenco, verificato dai test
(docs/authorization.md; ASVS 8.1.1, 8.2.1, 8.3.1).

Deny by default: una route che non compare qui fa fallire la CI. Per ogni route
il test controlla anche che la dipendenza nel codice corrisponda al livello
dichiarato e che chi non ha la sessione giusta venga davvero respinto.
"""

from __future__ import annotations

import enum
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session


class Access(enum.StrEnum):
    PUBLIC = "pubblica"
    PARTIAL = "sessione parziale"  # solo password: serve per il secondo fattore
    ANY = "qualsiasi sessione"
    FULL = "sessione completa"


ROUTE_POLICY: dict[tuple[str, str], Access] = {
    ("GET", "/health"): Access.PUBLIC,
    ("POST", "/auth/register"): Access.PUBLIC,
    ("POST", "/auth/verify-email"): Access.PUBLIC,
    ("POST", "/auth/login"): Access.PUBLIC,
    ("POST", "/auth/totp/setup"): Access.PARTIAL,
    ("POST", "/auth/totp/confirm"): Access.PARTIAL,
    ("POST", "/auth/login/totp"): Access.PARTIAL,
    ("POST", "/auth/login/recovery"): Access.PARTIAL,
    ("POST", "/auth/logout"): Access.ANY,
    ("GET", "/me"): Access.FULL,
    ("GET", "/me/sessions"): Access.FULL,
    ("POST", "/me/sessions/{session_id}/revoke"): Access.FULL,
    ("POST", "/me/sessions/revoke-others"): Access.FULL,
    ("POST", "/me/password"): Access.FULL,
    ("POST", "/me/recovery-codes"): Access.FULL,
}

# Campi che nessuna risposta delle API può contenere (ASVS 8.2.3).
FORBIDDEN_RESPONSE_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "totp_secret",
        "totp_secret_encrypted",
        "totp_last_step",
        "token",
        "token_hash",
        "code_hash",
        "owner_id",
        "user_id",
        "is_active",
        "failed_second_factor",
    }
)


def owned_or_404(
    db: Session, model, object_id: uuid.UUID, owner_id: uuid.UUID, owner_column: str = "owner_id"
):
    """Oggetto dell'utente oppure 404. Il filtro sul proprietario è nella query:
    un oggetto altrui è indistinguibile da uno inesistente (ASVS 8.2.2; AC11)."""
    obj = db.scalar(
        select(model).where(model.id == object_id, getattr(model, owner_column) == owner_id)
    )
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Non trovato.")
    return obj
