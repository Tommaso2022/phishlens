"""Applicazione FastAPI del backend di PhishLens."""

import os

from fastapi import FastAPI

# La documentazione interattiva (/docs, /openapi.json) espone la mappa completa
# delle API: attiva solo in sviluppo (ASVS V13, Configurazione).
_debug = os.getenv("PHISHLENS_ENV", "production") == "development"

app = FastAPI(
    title="PhishLens",
    docs_url="/docs" if _debug else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _debug else None,
)


@app.get("/health")
def health() -> dict[str, str]:
    """Controllo di stato usato da Docker: non rivela versioni né configurazione."""
    return {"status": "ok"}
