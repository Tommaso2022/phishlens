"""Login in due passi, TOTP obbligatorio, codici di recupero, logout
(passo 3.3; docs/authentication.md, sezioni 1, 3, 4, 5; ADR-003).

Negli errori di autenticazione la risposta viene restituita, non sollevata come
eccezione: così la transazione viene confermata e restano salvati l'evento di
audit e il contatore dei tentativi. Un'eccezione li annullerebbe, e un attaccante
potrebbe provare all'infinito senza lasciare traccia.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
from phishlens_db.models import RecoveryCode, SessionStage, User, UserSession
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from phishlens_backend import audit
from phishlens_backend.net import ip_prefix
from phishlens_backend.schemas import (
    CodeIn,
    LoginIn,
    LoginOut,
    MeOut,
    Message,
    RecoveryIn,
    TotpConfirmOut,
    TotpSetupOut,
)
from phishlens_backend.security import passwords, totp
from phishlens_backend.services import DbSession, Services, Svc
from phishlens_backend.sessions import (
    AnySession,
    Current,
    FullSession,
    PartialSession,
    end_session,
    start_session,
)

router = APIRouter(tags=["accesso"])

INVALID = "Credenziali non valide."
MAX_SECOND_FACTOR_FAILURES = 5
_DUMMY_HASH = passwords.hash_password("hash fittizio per tempi di risposta uniformi")


def _error(code: int, detail: str, retry_after: int | None = None) -> JSONResponse:
    headers = {"Retry-After": str(retry_after)} if retry_after else None
    return JSONResponse(status_code=code, content={"detail": detail}, headers=headers)


@router.post("/auth/login", response_model=LoginOut, responses={401: {"model": Message}})
def login(data: LoginIn, request: Request, response: Response, db: DbSession, svc: Svc):
    ip = ip_prefix(request)
    decision = svc.throttle.check(data.email, ip)
    if not decision.allowed:
        audit.record(db, "login_rallentato", ip_prefix=ip)
        return _error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Troppi tentativi, riprova più tardi.",
            decision.retry_after,
        )

    user = db.scalar(select(User).where(User.email == data.email))
    # Verifica sempre un hash, anche se l'utente non esiste: tempi simili (ASVS 6.3.8).
    ok = passwords.verify_password(user.password_hash if user else _DUMMY_HASH, data.password)
    if not ok or user is None or not user.is_active:
        if svc.throttle.failure(data.email, ip):
            audit.record(
                db, "allarme_tentativi_account", user_id=user.id if user else None, ip_prefix=ip
            )
        audit.record(db, "login_fallito", user_id=user.id if user else None, ip_prefix=ip)
        return _error(status.HTTP_401_UNAUTHORIZED, INVALID)
    if user.email_verified_at is None:
        return _error(status.HTTP_403_FORBIDDEN, "Conferma prima il tuo indirizzo email.")

    svc.throttle.success(data.email, ip)
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(data.password)
    start_session(db, svc, response, request, user, SessionStage.PARTIAL)
    audit.record(db, "login_password_ok", user_id=user.id, ip_prefix=ip)
    return LoginOut(next="totp" if user.totp_enabled_at else "totp_setup")


def _promote(
    db: Session, svc: Services, request: Request, response: Response, cur: Current
) -> None:
    """Dopo il secondo fattore: nuova sessione completa, quella parziale viene cancellata.
    Token nuovo a ogni cambio di livello (ASVS 7.2.4)."""
    db.execute(delete(UserSession).where(UserSession.id == cur.session.id))
    start_session(db, svc, response, request, cur.user, SessionStage.FULL)


def _second_factor_failed(db: Session, cur: Current, ip: str, event: str) -> JSONResponse:
    cur.session.failed_second_factor += 1
    audit.record(db, event, user_id=cur.user.id, ip_prefix=ip)
    if cur.session.failed_second_factor >= MAX_SECOND_FACTOR_FAILURES:
        db.execute(delete(UserSession).where(UserSession.id == cur.session.id))
        audit.record(db, "sessione_parziale_annullata", user_id=cur.user.id, ip_prefix=ip)
    return _error(status.HTTP_401_UNAUTHORIZED, "Codice non valido.")


@router.post("/auth/totp/setup", response_model=TotpSetupOut)
def totp_setup(cur: PartialSession, db: DbSession, svc: Svc):
    if cur.user.totp_enabled_at is not None:
        return _error(status.HTTP_409_CONFLICT, "Il secondo fattore è già configurato.")
    secret = totp.new_secret()
    cur.user.totp_secret_encrypted = svc.box.encrypt(secret, cur.user.id)
    return TotpSetupOut(secret=secret, uri=totp.provisioning_uri(secret, cur.user.email))


def _accept_step(db: Session, user: User, step: int) -> bool:
    """Registra il passo usato; False se era già stato usato (codice riutilizzato)."""
    return (
        db.scalar(
            update(User)
            .where(
                User.id == user.id, (User.totp_last_step.is_(None)) | (User.totp_last_step < step)
            )
            .values(totp_last_step=step)
            .returning(User.id)
        )
        is not None
    )


@router.post("/auth/totp/confirm", response_model=TotpConfirmOut)
def totp_confirm(
    data: CodeIn, request: Request, response: Response, cur: PartialSession, db: DbSession, svc: Svc
):
    ip = ip_prefix(request)
    user = cur.user
    if user.totp_enabled_at is not None or user.totp_secret_encrypted is None:
        return _error(status.HTTP_409_CONFLICT, "Nessuna configurazione in corso.")
    secret = svc.box.decrypt(user.totp_secret_encrypted, user.id)
    step = totp.matching_step(secret, data.code, svc.clock())
    if step is None or not _accept_step(db, user, step):
        return _second_factor_failed(db, cur, ip, "totp_conferma_fallita")

    user.totp_enabled_at = datetime.now(UTC)
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = totp.new_recovery_codes()
    db.add_all(RecoveryCode(user_id=user.id, code_hash=totp.hash_recovery(c)) for c in codes)
    _promote(db, svc, request, response, cur)
    audit.record(db, "totp_attivato", user_id=user.id, ip_prefix=ip)
    return TotpConfirmOut(recovery_codes=codes)


@router.post("/auth/login/totp", response_model=Message)
def login_totp(
    data: CodeIn, request: Request, response: Response, cur: PartialSession, db: DbSession, svc: Svc
):
    ip = ip_prefix(request)
    user = cur.user
    if user.totp_enabled_at is None or user.totp_secret_encrypted is None:
        return _error(status.HTTP_409_CONFLICT, "Configura prima il secondo fattore.")
    secret = svc.box.decrypt(user.totp_secret_encrypted, user.id)
    step = totp.matching_step(secret, data.code, svc.clock())
    if step is None or not _accept_step(db, user, step):
        return _second_factor_failed(db, cur, ip, "totp_fallito")
    _promote(db, svc, request, response, cur)
    audit.record(db, "login_ok", user_id=user.id, ip_prefix=ip, details={"fattore": "totp"})
    return Message(detail="Accesso completato.")


@router.post("/auth/login/recovery", response_model=Message)
def login_recovery(
    data: RecoveryIn,
    request: Request,
    response: Response,
    cur: PartialSession,
    db: DbSession,
    svc: Svc,
):
    ip = ip_prefix(request)
    normalized = totp.normalize_recovery(data.code)
    candidates = db.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == cur.user.id, RecoveryCode.used_at.is_(None)
        )
    ).all()
    match = next(
        (c for c in candidates if passwords.verify_password(c.code_hash, normalized)), None
    )
    # Segnato come usato con un UPDATE condizionale: monouso anche in parallelo (T-11).
    used = (
        match is not None
        and db.scalar(
            update(RecoveryCode)
            .where(RecoveryCode.id == match.id, RecoveryCode.used_at.is_(None))
            .values(used_at=datetime.now(UTC))
            .returning(RecoveryCode.id)
        )
        is not None
    )
    if not used:
        return _second_factor_failed(db, cur, ip, "codice_recupero_fallito")
    _promote(db, svc, request, response, cur)
    left = len(candidates) - 1
    audit.record(
        db,
        "login_ok",
        user_id=cur.user.id,
        ip_prefix=ip,
        details={"fattore": "codice_recupero", "codici_rimasti": left},
    )
    return Message(detail=f"Accesso completato. Codici di recupero rimasti: {left}.")


@router.post("/auth/logout", response_model=Message)
def logout(request: Request, response: Response, cur: AnySession, db: DbSession, svc: Svc):
    end_session(db, svc, response, cur.session)
    audit.record(db, "logout", user_id=cur.user.id, ip_prefix=ip_prefix(request))
    return Message(detail="Disconnesso.")


@router.get("/me", response_model=MeOut)
def me(cur: FullSession, db: DbSession):
    left = db.scalar(
        select(func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == cur.user.id, RecoveryCode.used_at.is_(None))
    )
    return MeOut(
        email=cur.user.email,
        totp_enabled=cur.user.totp_enabled_at is not None,
        recovery_codes_left=left,
        daily_quota=cur.user.daily_quota,
    )
