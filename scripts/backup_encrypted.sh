#!/usr/bin/env bash
# ==============================================================================
# Exposight Automated Encrypted Database Backup Script (age encryption)
#
# Generates a compressed, age-encrypted PostgreSQL dump from the production
# database container.
#
# Security Invariants (G6.1):
# 1. Enforces owner-only permissions (077 umask, 0600 file modes).
# 2. Public key only on host: encryption uses the age public key recipient (age1...)
#    or a public recipient file (/etc/exposight/backup_age_recipient.pub).
#    Private keys (AGE-SECRET-KEY-1...) are NEVER allowed on the production host.
# 3. Encrypted at rest before off-host transfer or local persistence.
# 4. Rotates backups, keeping the last 7 days.
#
# Usage:
#   ./scripts/backup_encrypted.sh [/path/to/backup/dir] [age_public_key_recipient] [recipient_file]
#
# Environment variables:
#   BACKUP_AGE_RECIPIENT: age public key (e.g. age1...)
#   BACKUP_AGE_RECIPIENTS_FILE: path to recipient public key file (default: /etc/exposight/backup_age_recipient.pub)
# ==============================================================================
set -euo pipefail

# Ensure generated backup files and directories are readable by owner only (chmod 700 / 600)
umask 077

# Run from the repository root so compose.prod.yml resolves even when started by cron
cd "$(dirname "$0")/.."

BACKUP_DIR="${1:-/var/backups/exposight}"
AGE_RECIPIENT="${2:-${BACKUP_AGE_RECIPIENT:-}}"
AGE_RECIPIENTS_FILE="${3:-${BACKUP_AGE_RECIPIENTS_FILE:-/etc/exposight/backup_age_recipient.pub}}"

# Resolve age recipient: strictly require public key, reject private keys
RECIPIENT_ARGS=()
if [ -n "${AGE_RECIPIENT}" ]; then
    if [[ "${AGE_RECIPIENT}" == *"AGE-SECRET-KEY-"* ]]; then
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: Secret/private key provided! Only age public recipient keys (age1...) are permitted on host." >&2
        exit 1
    fi
    if [[ "${AGE_RECIPIENT}" != age1* ]]; then
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: Invalid age recipient public key: must start with 'age1'." >&2
        exit 1
    fi
    RECIPIENT_ARGS=(-r "${AGE_RECIPIENT}")
elif [ -f "${AGE_RECIPIENTS_FILE}" ]; then
    if grep -q "AGE-SECRET-KEY-" "${AGE_RECIPIENTS_FILE}" 2>/dev/null; then
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: Secret/private key found in recipient file! Only age public recipient keys (age1...) are permitted on host." >&2
        exit 1
    fi
    RECIPIENT_ARGS=(-R "${AGE_RECIPIENTS_FILE}")
else
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: No age public key recipient provided!" >&2
    echo "Provide public recipient key via argument, BACKUP_AGE_RECIPIENT env var, or file at ${AGE_RECIPIENTS_FILE}." >&2
    echo "Note: The private key must remain safely stored off-host and must NEVER be placed on this VM." >&2
    exit 1
fi

# Verify age command is installed
if ! command -v age >/dev/null 2>&1; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: 'age' encryption tool is not installed or not in PATH." >&2
    echo "Install age via package manager (e.g., apt install age) before running encrypted backups." >&2
    exit 1
fi

TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
BACKUP_FILE="${BACKUP_DIR}/exposight_db_${TIMESTAMP}.sql.gz.age"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting encrypted database backup to ${BACKUP_FILE}..."

# pg_dump inside db container -> gzip -> age encrypt -> write to file
docker compose -f compose.prod.yml exec -T db \
  sh -c 'pg_dump --clean --if-exists -U "$POSTGRES_USER" "$POSTGRES_DB"' | \
  gzip -9 | \
  age "${RECIPIENT_ARGS[@]}" > "${BACKUP_FILE}"

# Verify file exists and is non-empty
if [ ! -s "${BACKUP_FILE}" ]; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: Encrypted backup file ${BACKUP_FILE} is missing or empty!" >&2
    exit 1
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Encrypted backup completed successfully ($(du -h "${BACKUP_FILE}" | cut -f1))."

# Retain last 7 days of backups (delete backups older than 7 days)
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Pruning encrypted backups older than 7 days..."
find "${BACKUP_DIR}" -name "exposight_db_*.sql.gz.age" -type f -mtime +6 -delete

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Encrypted backup rotation finished."
