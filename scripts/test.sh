#!/bin/sh
# Esegue tutti i test, compresi quelli del database.
# Avvia (se serve) il PostgreSQL di test di compose.yaml, con i dati in memoria,
# e passa ai test l'URL dell'amministratore letto da .env.
#   sh scripts/test.sh          tutti i test
#   sh scripts/test.sh db/tests solo una cartella
set -eu
docker compose --profile test up -d --wait db-test
pw=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)
PHISHLENS_TEST_ADMIN_URL="postgresql+psycopg://phishlens:${pw}@127.0.0.1:55432/postgres" \
  exec uv run pytest -q "$@"
