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
