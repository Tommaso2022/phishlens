"""Sessioni lato server (ADR-002; docs/authentication.md, sezione 7).

Il browser riceve un token casuale in un cookie HttpOnly, Secure, SameSite=Lax;
nel database c'è solo il suo hash. Una sessione "parziale" (solo password)
vale 5 minuti e serve solo per il secondo fattore; quella "completa" scade
dopo 30 minuti di inattività o 12 ore dal login.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, status
from phishlens_db.models import SessionStage, User, UserSession
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from phishlens_backend.security.tokens import hash_token, new_token
from phishlens_backend.services import DbSession, Services, Svc

PARTIAL_TTL = timedelta(minutes=5)
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TTL = timedelta(hours=12)
MAX_FULL_SESSIONS = 5
TOUCH_EVERY = timedelta(seconds=60)


def cookie_name(svc: Services) -> str:
    # Il prefisso __Host- obbliga il browser a rifiutare cookie impostati da
    # sottodomini o senza Secure: possibile solo quando il cookie è Secure.
    return "__Host-phishlens_session" if svc.settings.cookie_secure else "phishlens_session"


def start_session(
    db: Session,
    svc: Services,
    response: Response,
    request: Request,
    user: User,
    stage: SessionStage,
) -> UserSession:
    now = datetime.now(UTC)
    if stage == SessionStage.FULL:
        _trim_full_sessions(db, user.id)
    token, digest = new_token()
    sess = UserSession(
        token_hash=digest,
        user_id=user.id,
        stage=stage,
        last_seen_at=now,
        expires_at=now + (PARTIAL_TTL if stage == SessionStage.PARTIAL else ABSOLUTE_TTL),
        user_agent=(request.headers.get("user-agent") or "")[:200] or None,
    )
    db.add(sess)
    db.flush()
    response.set_cookie(
        cookie_name(svc),
        token,
        httponly=True,
        secure=svc.settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=int((sess.expires_at - now).total_seconds()),
    )
    return sess


def _trim_full_sessions(db: Session, user_id: uuid.UUID) -> None:
    """Al massimo 5 sessioni complete: si chiude la meno recente (sezione 7.2)."""
    ids = db.scalars(
        select(UserSession.id)
        .where(UserSession.user_id == user_id, UserSession.stage == SessionStage.FULL)
        .order_by(UserSession.last_seen_at.desc())
        .offset(MAX_FULL_SESSIONS - 1)
    ).all()
    if ids:
        db.execute(delete(UserSession).where(UserSession.id.in_(ids)))


def end_session(db: Session, svc: Services, response: Response, sess: UserSession) -> None:
    db.execute(delete(UserSession).where(UserSession.id == sess.id))
    response.delete_cookie(
        cookie_name(svc), path="/", secure=svc.settings.cookie_secure, httponly=True, samesite="lax"
    )


@dataclass
class Current:
    session: UserSession
    user: User


def _load(request: Request, db: Session, svc: Services) -> Current:
    token = request.cookies.get(cookie_name(svc))
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Accesso richiesto.")
    if not token or len(token) > 100:
        raise unauthorized
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    now = datetime.now(UTC)
    if sess is None:
        raise unauthorized
    expired = sess.expires_at <= now or (
        sess.stage == SessionStage.FULL and sess.last_seen_at <= now - IDLE_TIMEOUT
    )
    user = db.get(User, sess.user_id)
    if expired or user is None or not user.is_active:
        db.execute(delete(UserSession).where(UserSession.id == sess.id))
        raise unauthorized
    if now - sess.last_seen_at > TOUCH_EVERY:
        sess.last_seen_at = now
    return Current(sess, user)


def partial_session(request: Request, db: DbSession, svc: Svc) -> Current:
    cur = _load(request, db, svc)
    if cur.session.stage != SessionStage.PARTIAL:
        raise HTTPException(status.HTTP_409_CONFLICT, "Accesso già completato.")
    return cur


def full_session(request: Request, db: DbSession, svc: Svc) -> Current:
    cur = _load(request, db, svc)
    if cur.session.stage != SessionStage.FULL:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Completa l'accesso con il secondo fattore."
        )
    return cur


def any_session(request: Request, db: DbSession, svc: Svc) -> Current:
    return _load(request, db, svc)


PartialSession = Annotated[Current, Depends(partial_session)]
FullSession = Annotated[Current, Depends(full_session)]
AnySession = Annotated[Current, Depends(any_session)]
