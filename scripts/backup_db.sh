#!/usr/bin/env bash
# ==============================================================================
# Exposight Automated Database Backup Script
#
# Generates a compressed, timestamped PostgreSQL dump from the production
# database container, enforces owner-only permissions (077 umask), and rotates
# backups keeping the last 7 days.
#
# Usage:
#   ./scripts/backup_db.sh [/path/to/backup/dir]
# ==============================================================================
set -euo pipefail

# Ensure generated backup files and directories are readable by owner only (chmod 700 / 600)
umask 077

# Run from the repository root so compose.prod.yml resolves even when started by cron
cd "$(dirname "$0")/.."

BACKUP_DIR="${1:-/var/backups/exposight}"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
BACKUP_FILE="${BACKUP_DIR}/exposight_db_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting database backup to ${BACKUP_FILE}..."

# pg_dump runs inside the db container using that container's own POSTGRES_USER/POSTGRES_DB.
# --clean --if-exists makes the dump restorable over an existing database.
# Exits non-zero if docker compose or pg_dump fails (pipefail enabled).
docker compose -f compose.prod.yml exec -T db \
  sh -c 'pg_dump --clean --if-exists -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip -9 > "${BACKUP_FILE}"

# Verify file exists and is non-empty
if [ ! -s "${BACKUP_FILE}" ]; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: Backup file ${BACKUP_FILE} is missing or empty!" >&2
    exit 1
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Backup completed successfully ($(du -h "${BACKUP_FILE}" | cut -f1))."

# Retain last 7 days of backups (delete backups older than 7 days)
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Pruning backups older than 7 days..."
find "${BACKUP_DIR}" -name "exposight_db_*.sql.gz" -type f -mtime +7 -delete

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Backup rotation finished."
