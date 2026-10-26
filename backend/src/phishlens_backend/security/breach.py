"""Controllo delle password violate con Pwned Passwords di Have I Been Pwned.

k-anonymity: si invia solo il prefisso di 5 caratteri dell'hash SHA-1 della
password; HIBP risponde con tutti i suffissi noti per quel prefisso e il
confronto avviene qui. La password e il suo hash completo non lasciano mai
il backend. Con "Add-Padding" la risposta ha dimensione simile per ogni prefisso.

Se il servizio non risponde, il controllo è considerato non disponibile (None):
la registrazione prosegue con i soli controlli locali (rischio residuo R5).
"""

from __future__ import annotations

import hashlib

import httpx

API = "https://api.pwnedpasswords.com/range/"
TIMEOUT = httpx.Timeout(3.0)
MAX_RESPONSE = 2 * 1024 * 1024


class BreachChecker:
    def __init__(self, client: httpx.Client | None = None):
        self._client = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)

    def is_breached(self, password: str) -> bool | None:
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        try:
            r = self._client.get(API + prefix, headers={"Add-Padding": "true"})
        except httpx.HTTPError:
            return None
        if r.status_code != 200 or len(r.content) > MAX_RESPONSE:
            return None
        for line in r.text.splitlines():
            candidate, _, count = line.partition(":")
            if candidate.strip().upper() == suffix and count.strip() not in ("", "0"):
                return True  # le righe con conteggio 0 sono solo riempitivo
        return False


class DisabledBreachChecker:
    """Usato quando HIBP è disattivato da configurazione."""

    def is_breached(self, password: str) -> bool | None:
        return None
