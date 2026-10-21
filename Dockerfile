# syntax=docker/dockerfile:1
#
# Un solo Dockerfile per i tre servizi Python. Il servizio si sceglie con
# l'argomento SERVICE (backend, worker o fetcher): ogni immagine contiene
# solo le dipendenze di quel servizio e di core.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_VERSION=0.13.4

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---- Fase di build: crea l'ambiente virtuale -------------------------------
FROM ${PYTHON_IMAGE} AS build
ARG SERVICE
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python3.12
WORKDIR /app
COPY . .
# --frozen: usa uv.lock così com'è e verifica gli hash; fallisce se non è allineato.
# --no-editable: installa il codice dentro .venv, così l'immagine finale non
# ha bisogno dei sorgenti.
RUN test -n "$SERVICE" && \
    uv sync --frozen --no-dev --no-editable --package "phishlens-${SERVICE}"

# ---- Immagine finale: solo Python e l'ambiente virtuale ---------------------
FROM ${PYTHON_IMAGE} AS runtime
# Utente senza privilegi, senza shell di login e senza cartella home.
RUN groupadd --system --gid 10001 phishlens && \
    useradd --system --uid 10001 --gid phishlens --no-create-home \
        --shell /usr/sbin/nologin phishlens
# I file restano di proprietà di root: il processo li legge ma non può modificarli.
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
USER 10001:10001
