"""Protezione CSRF (ASVS V3; threat model T-01; docs/authentication.md).

Due barriere indipendenti, applicate a tutte le richieste che modificano dati
(POST, PUT, PATCH, DELETE):

1. Origine: se il browser indica l'origine della richiesta (Origin, o in sua
   assenza Referer), deve essere quella dell'applicazione. Vale anche senza
   sessione: blocca il "login CSRF", cioè far entrare la vittima nell'account
   dell'attaccante.
2. Token: se la richiesta porta il cookie di sessione, deve portare anche
   l'intestazione X-CSRF-Token con il valore derivato da quella sessione.
   Il valore è nel cookie leggibile "csrf", che il frontend copia
   nell'intestazione: un sito esterno non può leggerlo né indovinarlo.

Il token è SHA-256 di un prefisso fisso e del token di sessione: dipende dalla
sessione, cambia a ogni login e non richiede colonne in più nel database;
il token di sessione (256 bit casuali) non si ricava dal suo hash.
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HEADER = "x-csrf-token"


def csrf_token_for(session_token: str) -> str:
    return hashlib.sha256(b"phishlens-csrf-v1:" + session_token.encode()).hexdigest()


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower() if p.scheme and p.netloc else ""


class CsrfMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, allowed_origin: str, session_cookie: str):
        super().__init__(app)
        self.allowed = _origin(allowed_origin)
        self.session_cookie = session_cookie

    async def dispatch(self, request: Request, call_next):
        if request.method in UNSAFE:
            source = request.headers.get("origin") or request.headers.get("referer")
            if source and _origin(source) != self.allowed:
                return _forbidden("Origine della richiesta non consentita.")
            session = request.cookies.get(self.session_cookie)
            if session:
                sent = request.headers.get(HEADER, "")
                if not hmac.compare_digest(sent, csrf_token_for(session)):
                    return _forbidden("Token CSRF mancante o non valido.")
        return await call_next(request)


def _forbidden(detail: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": detail})
