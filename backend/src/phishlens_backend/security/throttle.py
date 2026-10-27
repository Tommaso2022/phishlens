"""Difese contro credential stuffing e brute force sul login
(docs/authentication.md, sezione 3; ASVS 6.1.1, 6.3.1; threat model AC10).

- Per coppia account + IP: dopo 5 errori, attesa che raddoppia a ogni errore
  (1 s, 2 s, 4 s, ...) fino a 15 minuti. Rallenta l'attaccante senza bloccare
  l'utente vero, che si collega da un'altra rete.
- Per IP, su tutti gli account: massimo 30 tentativi ogni 15 minuti.
- Per account, da tutti gli IP: oltre 50 errori in un'ora solo un evento di
  audit, nessun blocco: altrimenti chiunque conosca un'email potrebbe impedire
  l'accesso al legittimo proprietario.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import redis

FREE_FAILURES = 5
MAX_DELAY = 15 * 60
IP_LIMIT, IP_WINDOW = 30, 15 * 60
ACCOUNT_ALERT, ACCOUNT_WINDOW = 50, 3600


def _key(*parts: str) -> str:
    return "lt:" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


@dataclass
class Decision:
    allowed: bool
    retry_after: int = 0


class LoginThrottle:
    def __init__(self, client: redis.Redis):
        self._r = client

    def check(self, email: str, ip: str) -> Decision:
        try:
            ip_count = self._r.incr(_key("ip", ip))
            if ip_count == 1:
                self._r.expire(_key("ip", ip), IP_WINDOW)
            if ip_count > IP_LIMIT:
                return Decision(False, int(self._r.ttl(_key("ip", ip))) or IP_WINDOW)
            wait = self._r.ttl(_key("lock", email, ip))
        except redis.RedisError:
            return Decision(False, 60)  # senza Redis nessuna protezione: meglio fermarsi
        return Decision(False, int(wait)) if wait and wait > 0 else Decision(True)

    def failure(self, email: str, ip: str) -> bool:
        """Registra un errore. True se l'account ha superato la soglia d'allarme."""
        try:
            fails = self._r.incr(_key("fail", email, ip))
            self._r.expire(_key("fail", email, ip), MAX_DELAY * 2)
            if fails > FREE_FAILURES:
                delay = min(2 ** (fails - FREE_FAILURES - 1), MAX_DELAY)
                self._r.set(_key("lock", email, ip), 1, ex=delay)
            total = self._r.incr(_key("acct", email))
            if total == 1:
                self._r.expire(_key("acct", email), ACCOUNT_WINDOW)
            return total == ACCOUNT_ALERT + 1
        except redis.RedisError:
            return False

    def success(self, email: str, ip: str) -> None:
        try:
            self._r.delete(_key("fail", email, ip), _key("lock", email, ip))
        except redis.RedisError:
            pass
