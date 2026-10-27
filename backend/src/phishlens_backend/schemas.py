"""Schemi delle richieste: validazione stretta e campi sconosciuti rifiutati
(docs/validation.md; ASVS 2.2.1, 8.2.3 contro il mass assignment)."""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field


def _lower(value: str) -> str:
    return value.lower()


Email = Annotated[EmailStr, Field(max_length=254), AfterValidator(_lower)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class RegisterIn(StrictModel):
    email: Email
    # Limite largo qui; la policy (15-128 caratteri) restituisce messaggi chiari.
    password: str = Field(min_length=1, max_length=1024)


class VerifyEmailIn(StrictModel):
    token: str = Field(min_length=20, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class Message(BaseModel):
    detail: str


class LoginIn(StrictModel):
    email: Email
    password: str = Field(min_length=1, max_length=1024)


class LoginOut(BaseModel):
    next: str  # "totp" oppure "totp_setup"


class CodeIn(StrictModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class RecoveryIn(StrictModel):
    code: str = Field(min_length=16, max_length=24, pattern=r"^[A-Za-z2-7 -]+$")


class TotpSetupOut(BaseModel):
    secret: str
    uri: str


class TotpConfirmOut(BaseModel):
    recovery_codes: list[str]
    detail: str = (
        "Secondo fattore attivato. Conserva questi codici: non verranno mostrati di nuovo."
    )


class MeOut(BaseModel):
    email: str
    totp_enabled: bool
    recovery_codes_left: int
    daily_quota: int
