"""Servizio fetcher: per ora espone solo il controllo di stato.

La logica di richiesta verso gli URL analizzati, con le difese SSRF,
arriverà nella Fase 4 (docs/validation.md, sezione 4).
"""

from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
