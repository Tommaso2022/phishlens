"""Verifica d'integrità dei file del modello (threat model T-08, abuse case AC6).

Il worker carica un modello solo se il suo hash SHA-256 coincide con quello
registrato in ml/model-registry.json. Un file sostituito o danneggiato fa
fallire l'avvio invece di produrre verdetti sbagliati.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

CHUNK = 1024 * 1024


class IntegrityError(Exception):
    """Il file non corrisponde all'hash atteso."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_file(path: Path, expected_sha256: str) -> None:
    """Solleva IntegrityError se l'hash del file non è quello atteso."""
    actual = sha256_file(path)
    # Confronto a tempo costante: buona abitudine per ogni verifica di valori segreti o firme.
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise IntegrityError(
            f"{Path(path).name}: hash {actual[:16]}..., atteso {expected_sha256[:16]}..."
        )
