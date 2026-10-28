"""Applicazione FastAPI del backend di PhishLens.

Avvio: uvicorn --factory phishlens_backend.main:create_app
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from phishlens_backend.config import Settings, get_settings
from phishlens_backend.routers import account, auth, login
from phishlens_backend.security.csrf import CsrfMiddleware
from phishlens_backend.services import Services
from phishlens_backend.sessions import cookie_name


async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Errori di validazione senza il valore ricevuto.

    La risposta predefinita di FastAPI ripete l'input: con un modulo di
    registrazione significherebbe rimandare indietro la password.
    """
    errors = [
        {"campo": ".".join(str(p) for p in e["loc"][1:]), "errore": e["msg"]} for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": errors}
    )


def create_app(settings: Settings | None = None, svc: Services | None = None) -> FastAPI:
    settings = settings or get_settings()
    # La documentazione interattiva espone la mappa delle API: solo in sviluppo (V13).
    docs = settings.is_development
    app = FastAPI(
        title="PhishLens",
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.services = svc or Services.from_settings(settings)
    app.add_middleware(
        CsrfMiddleware,
        allowed_origin=settings.base_url,
        session_cookie=cookie_name(app.state.services),
    )
    app.add_exception_handler(RequestValidationError, validation_error)
    app.include_router(auth.router)
    app.include_router(login.router)
    app.include_router(account.router)

    @app.get("/health")
    def health() -> dict[str, str]:
        """Controllo di stato usato da Docker: non rivela versioni né configurazione."""
        return {"status": "ok"}

    return app
