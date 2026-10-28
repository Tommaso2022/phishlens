"""Gestione dell'account: sessioni attive, cambio password, codici di recupero
(passo 3.4; docs/authentication.md, sezioni 5 e 7; ASVS 7.4.3, 7.5.1, 7.5.2).

Le operazioni che toccano l'autenticazione richiedono di autenticarsi di nuovo
anche con una sessione valida: chi trovasse un computer lasciato aperto non
potrebbe cambiare la password né prendersi i codici di recupero.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Request, status
from fastapi.responses import JSONResponse
from phishlens_db.models import RecoveryCode, SessionStage, UserSession
from sqlalchemy import delete, select

from phishlens_backend import audit
from phishlens_backend.mailer import Mail
from phishlens_backend.net import ip_prefix
from phishlens_backend.routers.auth import _send
from phishlens_backend.routers.login import accept_step
from phishlens_backend.schemas import (
    Message,
    PasswordChangeIn,
    PasswordConfirmIn,
    ReauthIn,
    RecoveryCodesOut,
    SessionOut,
)
from phishlens_backend.security import passwords, totp
from phishlens_backend.services import DbSession, Services, Svc
from phishlens_backend.sessions import Current, FullSession

router = APIRouter(prefix="/me", tags=["account"])


def _error(code: int, detail) -> JSONResponse:
    return JSONResponse(status_code=code, content={"detail": detail})


def _check_password(db, svc: Services, cur: Current, password: str, ip: str) -> JSONResponse | None:
    decision = svc.throttle.check(cur.user.email, ip)
    if not decision.allowed:
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, "Troppi tentativi, riprova più tardi.")
    if not passwords.verify_password(cur.user.password_hash, password):
        svc.throttle.failure(cur.user.email, ip)
        audit.record(db, "riautenticazione_fallita", user_id=cur.user.id, ip_prefix=ip)
        return _error(status.HTTP_401_UNAUTHORIZED, "Password non corretta.")
    return None


def _check_password_and_totp(
    db, svc: Services, cur: Current, password: str, code: str, ip: str
) -> JSONResponse | None:
    """Nuova autenticazione completa (ASVS 7.5.1). None se tutto è corretto."""
    if (error := _check_password(db, svc, cur, password, ip)) is not None:
        return error
    secret = svc.box.decrypt(cur.user.totp_secret_encrypted, cur.user.id)
    step = totp.matching_step(secret, code, svc.clock())
    if step is None or not accept_step(db, cur.user, step):
        svc.throttle.failure(cur.user.email, ip)
        audit.record(
            db,
            "riautenticazione_fallita",
            user_id=cur.user.id,
            ip_prefix=ip,
            details={"fattore": "totp"},
        )
        return _error(status.HTTP_401_UNAUTHORIZED, "Codice non valido.")
    return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(cur: FullSession, db: DbSession):
    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == cur.user.id, UserSession.stage == SessionStage.FULL)
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    return [
        SessionOut(
            id=str(s.id),
            created_at=_iso(s.created_at),
            last_seen_at=_iso(s.last_seen_at),
            user_agent=s.user_agent,
            ip_prefix=s.ip_prefix,
            current=s.id == cur.session.id,
        )
        for s in rows
    ]


@router.post("/sessions/{session_id}/revoke", response_model=Message)
def revoke_session(
    session_id: uuid.UUID,
    data: PasswordConfirmIn,
    request: Request,
    cur: FullSession,
    db: DbSession,
    svc: Svc,
):
    ip = ip_prefix(request)
    if (error := _check_password(db, svc, cur, data.password, ip)) is not None:
        return error
    # Il filtro sul proprietario fa parte della query: una sessione altrui risulta
    # semplicemente inesistente (404, non 403: non si rivela che esiste; ASVS 8.2.2).
    deleted = db.scalar(
        delete(UserSession)
        .where(UserSession.id == session_id, UserSession.user_id == cur.user.id)
        .returning(UserSession.id)
    )
    if deleted is None:
        return _error(status.HTTP_404_NOT_FOUND, "Sessione non trovata.")
    audit.record(db, "sessione_chiusa", user_id=cur.user.id, ip_prefix=ip)
    return Message(detail="Sessione chiusa.")


@router.post("/sessions/revoke-others", response_model=Message)
def revoke_other_sessions(
    data: PasswordConfirmIn, request: Request, cur: FullSession, db: DbSession, svc: Svc
):
    ip = ip_prefix(request)
    if (error := _check_password(db, svc, cur, data.password, ip)) is not None:
        return error
    n = _revoke_others(db, cur)
    audit.record(
        db, "altre_sessioni_chiuse", user_id=cur.user.id, ip_prefix=ip, details={"sessioni": n}
    )
    return Message(detail=f"Sessioni chiuse: {n}.")


def _revoke_others(db, cur: Current) -> int:
    ids = db.scalars(
        delete(UserSession)
        .where(UserSession.user_id == cur.user.id, UserSession.id != cur.session.id)
        .returning(UserSession.id)
    ).all()
    return len(ids)


@router.post("/password", response_model=Message)
def change_password(
    data: PasswordChangeIn,
    request: Request,
    background: BackgroundTasks,
    cur: FullSession,
    db: DbSession,
    svc: Svc,
):
    ip = ip_prefix(request)
    error = _check_password_and_totp(db, svc, cur, data.current_password, data.totp_code, ip)
    if error is not None:
        return error
    if data.new_password == data.current_password:
        return _error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            ["La nuova password deve essere diversa da quella attuale."],
        )
    problems = passwords.policy_problems(data.new_password, cur.user.email)
    if not problems and svc.breach.is_breached(data.new_password):
        problems.append("Questa password compare in violazioni di dati note: scegline un'altra.")
    if problems:
        return _error(status.HTTP_422_UNPROCESSABLE_CONTENT, problems)

    cur.user.password_hash = passwords.hash_password(data.new_password)
    closed = _revoke_others(db, cur) if data.revoke_other_sessions else 0
    audit.record(
        db,
        "password_cambiata",
        user_id=cur.user.id,
        ip_prefix=ip,
        details={"altre_sessioni_chiuse": closed},
    )
    background.add_task(
        _send,
        svc,
        Mail(
            to=cur.user.email,
            subject="La tua password è stata cambiata - PhishLens",
            body=(
                "Ciao,\n\nla password del tuo account PhishLens è stata appena cambiata.\n\n"
                "Se non sei stato tu, usa la procedura di recupero dell'account e contatta "
                "l'amministratore.\n"
            ),
        ),
    )
    return Message(detail="Password cambiata.")


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
def regenerate_recovery_codes(
    data: ReauthIn, request: Request, cur: FullSession, db: DbSession, svc: Svc
):
    ip = ip_prefix(request)
    error = _check_password_and_totp(db, svc, cur, data.password, data.totp_code, ip)
    if error is not None:
        return error
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == cur.user.id))
    codes = totp.new_recovery_codes()
    db.add_all(RecoveryCode(user_id=cur.user.id, code_hash=totp.hash_recovery(c)) for c in codes)
    audit.record(db, "codici_recupero_rigenerati", user_id=cur.user.id, ip_prefix=ip)
    return RecoveryCodesOut(recovery_codes=codes)
