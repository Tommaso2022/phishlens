"""Hashing e policy delle password (docs/authentication.md, sezione 2; ASVS V6.2).

- Argon2id con i parametri raccomandati dalla libreria.
- 15-128 caratteri, nessuna regola di composizione, nessuna trasformazione:
  la password è usata esattamente come l'utente l'ha scritta (ASVS 6.2.8).
- Rifiutate se compaiono tra le password più diffuse, se contengono parole del
  contesto (anche con sostituzioni come 0 per o) o se risultano violate (HIBP).
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 15
MAX_LENGTH = 128  # limite contro il DoS sul calcolo dell'hash
CONTEXT_WORDS = ("phishlens", "phish", "lens", "phishing", "password", "admin", "root", "login")
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "@": "a", "5": "s", "$": "s", "7": "t"}
)

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    text = files("phishlens_backend").joinpath("data/common-passwords.txt").read_text("utf-8")
    return frozenset(line for line in text.splitlines() if line and not line.startswith("#"))


def policy_problems(password: str, email: str | None = None) -> list[str]:
    """Problemi della password secondo la policy locale (senza HIBP)."""
    if len(password) < MIN_LENGTH:
        return [f"La password deve avere almeno {MIN_LENGTH} caratteri."]
    if len(password) > MAX_LENGTH:
        return [f"La password può avere al massimo {MAX_LENGTH} caratteri."]
    problems = []
    lowered = password.lower()
    if lowered in common_passwords():
        problems.append("È una delle password più usate al mondo.")
    normalized = lowered.translate(_LEET)
    words = list(CONTEXT_WORDS)
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4:
            words.append(local)
    if any(w in lowered or w in normalized for w in words):
        problems.append(
            "Contiene il nome del servizio, del tuo indirizzo email o parole troppo prevedibili."
        )
    return problems
