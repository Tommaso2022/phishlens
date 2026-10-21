#!/bin/sh
# Genera il file .env con password casuali per l'ambiente di sviluppo.
# Non sovrascrive un .env esistente.
set -eu
if [ -e .env ]; then
  echo "Il file .env esiste già: non lo sovrascrivo." >&2
  exit 1
fi
umask 077
gen() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
{
  echo "# Generato da scripts/make-env.sh. Non committare."
  echo "POSTGRES_PASSWORD=$(gen)"
  echo "REDIS_PASSWORD=$(gen)"
} > .env
echo "Creato .env: solo il tuo utente può leggerlo."
