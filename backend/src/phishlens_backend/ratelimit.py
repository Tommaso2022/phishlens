"""Limiti di frequenza su Redis, a finestra fissa (docs/authentication.md, sezione 3).

Le chiavi contengono un hash dell'identità (IP, email), non il valore in chiaro.
Se Redis non risponde il limite è considerato superato: per le operazioni
protette meglio un errore temporaneo che nessuna protezione.
"""

from __future__ import annotations

import hashlib

import redis


class RateLimiter:
    def __init__(self, client: redis.Redis):
        self._redis = client

    def hit(self, name: str, identity: str, limit: int, window_seconds: int) -> bool:
        """Registra un tentativo; True se è ancora entro il limite."""
        digest = hashlib.sha256(identity.encode()).hexdigest()[:24]
        key = f"rl:{name}:{digest}"
        try:
            pipe = self._redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            count, _ = pipe.execute()
        except redis.RedisError:
            return False
        return int(count) <= limit
