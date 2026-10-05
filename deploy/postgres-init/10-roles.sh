#!/usr/bin/env bash
# ==============================================================================
# Exposight least-privilege database roles (v3.6b A1)
#
# Run once by the official postgres image entrypoint, as POSTGRES_USER, only
# when the data volume is empty (/docker-entrypoint-initdb.d). For an existing
# volume, follow the manual runbook in docs/DEPLOY.md instead.
#
# Creates:
#   OWNER_DB_USER  NOSUPERUSER; owns the database, runs Alembic, owns all tables.
#   APP_DB_USER    NOSUPERUSER, NOINHERIT; used by api and worker; owns nothing.
#                  Its table grants come from migration 0010.
# Passwords are passed as psql variables and never echoed.
# ==============================================================================
set -euo pipefail

: "${POSTGRES_DB:?POSTGRES_DB must be set}"
: "${OWNER_DB_USER:?OWNER_DB_USER must be set}"
: "${OWNER_DB_PASSWORD:?OWNER_DB_PASSWORD must be set}"
: "${APP_DB_USER:?APP_DB_USER must be set}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v db_name="$POSTGRES_DB" \
  -v owner_user="$OWNER_DB_USER" \
  -v owner_pw="$OWNER_DB_PASSWORD" \
  -v app_user="$APP_DB_USER" \
  -v app_pw="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE :"owner_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'owner_pw';
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  NOINHERIT PASSWORD :'app_pw';

-- The owner role owns the database, so (PostgreSQL 15+) it also controls schema public.
ALTER DATABASE :"db_name" OWNER TO :"owner_user";
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db_name" TO :"owner_user";
GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
SQL
