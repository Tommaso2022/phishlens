#!/bin/sh
# Eseguito da Postgres solo alla prima inizializzazione del volume dei dati.
# Crea i due utenti con privilegi diversi (threat model T-03):
#   phishlens_owner  proprietario dello schema, usato solo dalle migrazioni
#   phishlens_app    usato da backend e worker; i privilegi li assegna la migrazione
# L'utente amministratore ($POSTGRES_USER) non viene usato dall'applicazione.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$PHISHLENS_OWNER_DB_PASSWORD" -v app_pw="$PHISHLENS_APP_DB_PASSWORD" <<'SQL'
CREATE ROLE phishlens_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE phishlens_app LOGIN PASSWORD :'app_pw';
ALTER DATABASE phishlens OWNER TO phishlens_owner;
SQL
