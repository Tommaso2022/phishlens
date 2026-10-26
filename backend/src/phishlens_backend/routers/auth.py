"""Registrazione e verifica dell'email (passo 3.2; docs/authentication.md).

Anti-enumerazione: la risposta alla registrazione è identica che l'indirizzo
sia nuovo o già registrato; le email partono dopo la risposta, così anche i
tempi non rivelano nulla.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from phishlens_db.models import EmailToken, TokenPurpose, User
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from phishlens_backend import audit
from phishlens_backend.mailer import Mail
from phishlens_backend.net import ip_prefix
from phishlens_backend.schemas import Message, RegisterIn, VerifyEmailIn
from phishlens_backend.security import passwords
from phishlens_backend.security.tokens import hash_token, new_token
from phishlens_backend.services import DbSession, Services, Svc

router = APIRouter(prefix="/auth", tags=["autenticazione"])
log = logging.getLogger("phishlens.auth")

REGISTER_REPLY = "Se l'indirizzo è valido, riceverai un'email con le istruzioni."
DAY = 24 * 3600


def _send(svc: Services, mail: Mail) -> None:
    try:
        svc.mailer.send(mail)
    except Exception:  # l'errore non deve mai includere token o destinatario
        log.warning("Invio di un'email non riuscito")


def _verification_mail(svc: Services, to: str, token: str) -> Mail:
    link = f"{svc.settings.base_url}/verifica-email#token={token}"
    hours = svc.settings.verify_token_hours
    return Mail(
        to=to,
        subject="Conferma il tuo indirizzo email - PhishLens",
        body=(
            "Ciao,\n\n"
            f"per completare la registrazione a PhishLens apri questo link entro {hours} ore:\n\n"
            f"{link}\n\n"
            "Se non hai chiesto tu la registrazione, ignora questa email: senza conferma "
            "l'account non viene attivato.\n"
        ),
    )


def _already_registered_mail(to: str) -> Mail:
    return Mail(
        to=to,
        subject="Tentativo di registrazione - PhishLens",
        body=(
            "Ciao,\n\n"
            "qualcuno ha provato a registrare un account PhishLens con questo indirizzo, che è "
            "già registrato. Se sei stato tu, accedi oppure reimposta la password.\n\n"
            "Se non sei stato tu, puoi ignorare questa email: "
            "il tuo account non è stato modificato.\n"
        ),
    )


def _issue_verification(db: Session, svc: Services, user: User) -> str:
    """Invalida i link di verifica precedenti e ne crea uno nuovo."""
    now = datetime.now(UTC)
    db.execute(
        update(EmailToken)
        .where(
            EmailToken.user_id == user.id,
            EmailToken.purpose == TokenPurpose.VERIFY_EMAIL,
            EmailToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    token, digest = new_token()
    db.add(
        EmailToken(
            user_id=user.id,
            purpose=TokenPurpose.VERIFY_EMAIL,
            token_hash=digest,
            expires_at=now + timedelta(hours=svc.settings.verify_token_hours),
        )
    )
    return token


@router.post("/register", status_code=status.HTTP_202_ACCEPTED, response_model=Message)
def register(
    data: RegisterIn,
    request: Request,
    background: BackgroundTasks,
    db: DbSession,
    svc: Svc,
) -> Message:
    ip = ip_prefix(request)
    if not svc.limiter.hit("register:ip", ip, svc.settings.register_per_ip_per_day, DAY):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Troppi tentativi, riprova più tardi."
        )

    problems = passwords.policy_problems(data.password, data.email)
    breached = None if problems else svc.breach.is_breached(data.password)
    if breached:
        problems.append("Questa password compare in violazioni di dati note: scegline un'altra.")
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, problems)

    # Hash calcolato sempre, anche per indirizzi già registrati: tempi di risposta simili.
    password_hash = passwords.hash_password(data.password)
    user = db.scalar(select(User).where(User.email == data.email))
    # Massimo 3 email al giorno per indirizzo: niente "bombardamento" di una vittima.
    may_email = svc.limiter.hit("register:email", data.email, 3, DAY)

    if user is None:
        user = User(email=data.email, password_hash=password_hash)
        db.add(user)
        db.flush()
        token = _issue_verification(db, svc, user)
        audit.record(
            db,
            "registrazione",
            user_id=user.id,
            ip_prefix=ip,
            details={"hibp": "non disponibile" if breached is None else "ok"},
        )
        if may_email:
            background.add_task(_send, svc, _verification_mail(svc, data.email, token))
    elif user.email_verified_at is None:
        token = _issue_verification(db, svc, user)
        audit.record(db, "registrazione_ripetuta", user_id=user.id, ip_prefix=ip)
        if may_email:
            background.add_task(_send, svc, _verification_mail(svc, data.email, token))
    else:
        audit.record(db, "registrazione_indirizzo_esistente", user_id=user.id, ip_prefix=ip)
        if may_email:
            background.add_task(_send, svc, _already_registered_mail(data.email))
    return Message(detail=REGISTER_REPLY)


@router.post("/verify-email", response_model=Message)
def verify_email(
    data: VerifyEmailIn,
    request: Request,
    db: DbSession,
    svc: Svc,
) -> Message:
    ip = ip_prefix(request)
    if not svc.limiter.hit("verify:ip", ip, 20, 3600):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Troppi tentativi, riprova più tardi."
        )
    now = datetime.now(UTC)
    # Un solo UPDATE condizionale: il token si usa una volta sola anche con richieste
    # parallele (ASVS 2.3.4, threat model T-11).
    user_id = db.scalar(
        update(EmailToken)
        .where(
            EmailToken.token_hash == hash_token(data.token),
            EmailToken.purpose == TokenPurpose.VERIFY_EMAIL,
            EmailToken.used_at.is_(None),
            EmailToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(EmailToken.user_id)
    )
    if user_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Link non valido o scaduto.")
    db.execute(
        update(User)
        .where(User.id == user_id, User.email_verified_at.is_(None))
        .values(email_verified_at=now)
    )
    audit.record(db, "email_verificata", user_id=user_id, ip_prefix=ip)
    return Message(detail="Indirizzo confermato. Ora puoi accedere.")
