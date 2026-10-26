"""Token casuali: al client va il token, nel database solo il suo hash SHA-256."""

from __future__ import annotations

import hashlib
import secrets


def new_token() -> tuple[str, bytes]:
    token = secrets.token_urlsafe(32)  # 256 bit di entropia
    return token, hash_token(token)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii", "ignore")).digest()
