"""TOTP e codici di recupero (docs/authentication.md, sezioni 4 e 5; ASVS V6.5).

Segreto TOTP: serve in chiaro per verificare i codici, quindi non basta un hash.
È salvato cifrato con AES-256-GCM e una chiave che non sta nel database
(threat model I-03). L'ID dell'utente è usato come "dati associati": un segreto
copiato sulla riga di un altro utente non si decifra.

Verifica: passo di 30 secondi; si accettano il passo corrente e il precedente
(deviazione documentata da ASVS 6.5.5, per lo sfasamento degli orologi). Ogni
passo si usa una volta sola: lo garantisce un UPDATE condizionale su
users.totp_last_step, sicuro anche con richieste parallele.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import uuid

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from phishlens_backend.security import passwords

VERSION = b"\x01"
ISSUER = "PhishLens"
STEP = 30
RECOVERY_CODES = 10
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class SecretBox:
    """Cifratura del segreto TOTP con una chiave da 256 bit."""

    def __init__(self, key_b64: str):
        key = base64.urlsafe_b64decode(key_b64)
        if len(key) != 32:
            raise ValueError("PHISHLENS_TOTP_KEY deve contenere 32 byte in base64")
        self._aead = AESGCM(key)

    def encrypt(self, secret: str, user_id: uuid.UUID) -> bytes:
        nonce = secrets.token_bytes(12)
        return VERSION + nonce + self._aead.encrypt(nonce, secret.encode(), user_id.bytes)

    def decrypt(self, blob: bytes, user_id: uuid.UUID) -> str:
        if blob[:1] != VERSION:
            raise ValueError("versione di cifratura sconosciuta")
        return self._aead.decrypt(blob[1:13], blob[13:], user_id.bytes).decode()


def new_secret() -> str:
    return pyotp.random_base32()  # 160 bit da un generatore crittografico (ASVS 6.5.3)


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def matching_step(secret: str, code: str, now: float) -> int | None:
    """Il passo a cui corrisponde il codice (corrente o precedente), oppure None."""
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(now) // STEP
    for step in (current, current - 1):
        if hmac.compare_digest(totp.at(step * STEP), code):
            return step
    return None


def new_recovery_codes() -> list[str]:
    """Codici da 16 caratteri base32 (80 bit), mostrati come XXXX-XXXX-XXXX-XXXX."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(_B32) for _ in range(16))
        codes.append("-".join(raw[i : i + 4] for i in range(0, 16, 4)))
    return codes


def normalize_recovery(code: str) -> str:
    return code.replace("-", "").replace(" ", "").upper()


def hash_recovery(code: str) -> str:
    return passwords.hash_password(normalize_recovery(code))  # Argon2id (ASVS 6.5.2)
