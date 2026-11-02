#!/usr/bin/env bash
# ==============================================================================
# Exposight Remote Deploy Script
#
# Streamed to the Azure production VM via SSH:
#   ssh ... "bash -s -- <subcommand>"
#
# Subcommands:
#   precheck, backup, incoming, pull, up, verify
# ==============================================================================
set -euo pipefail

usage() {
    echo "Usage: $0 {precheck|backup|incoming|pull|up|verify}" >&2
    exit 2
}

phase_precheck() {
    if [ ! -d "/opt/exposight" ]; then
        echo "FAIL precheck: directory /opt/exposight does not exist" >&2
        exit 1
    fi
    cd /opt/exposight

    local branch
    branch=$(git branch --show-current 2>/dev/null || true)
    if [ "$branch" != "main" ]; then
        echo "FAIL precheck: current branch is not main (found '${branch:-detached}')" >&2
        exit 1
    fi

    local status
    status=$(git status --porcelain)
    if [ -n "$status" ]; then
        echo "FAIL precheck: git working tree is not clean" >&2
        exit 1
    fi

    local head_commit
    head_commit=$(git rev-parse HEAD 2>/dev/null || true)
    if [ -z "$head_commit" ]; then
        echo "FAIL precheck: failed to resolve HEAD commit" >&2
        exit 1
    fi

    local alembic_rev
    alembic_rev=$(docker compose -f compose.prod.yml exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"' 2>/dev/null || true)
    if [ -z "$alembic_rev" ]; then
        echo "FAIL precheck: failed to query alembic_version from db container" >&2
        exit 1
    fi

    mkdir -p "$HOME/deploy-logs"
    local utc_ts
    utc_ts=$(date -u +"%Y%m%d_%H%M%SZ")
    local pre_file="$HOME/deploy-logs/${utc_ts}-pre.txt"

    cat <<EOF > "$pre_file"
commit: $head_commit
revision: $alembic_rev
timestamp: $utc_ts
EOF

    echo "PRE_COMMIT=$head_commit"
    echo "PRE_REVISION=$alembic_rev"
    echo "OK precheck"
}

phase_backup() {
    cd /opt/exposight

    if ! sudo -n bash scripts/backup_db.sh /var/backups/exposight; then
        echo "FAIL backup: passwordless sudo needed for backup_db.sh" >&2
        exit 1
    fi

    if ! sudo -n chown -R "$(id -u -n):$(id -g -n)" /var/backups/exposight; then
        echo "FAIL backup: passwordless sudo needed for backup_db.sh" >&2
        exit 1
    fi

    local newest_backup
    newest_backup=$(ls -1t /var/backups/exposight/exposight_db_*.sql.gz 2>/dev/null | head -n 1 || true)
    if [ -z "$newest_backup" ] || [ ! -s "$newest_backup" ]; then
        echo "FAIL backup: newest backup file is missing or empty" >&2
        exit 1
    fi

    local backup_bytes
    backup_bytes=$(stat -c %s "$newest_backup" 2>/dev/null || wc -c < "$newest_backup" | tr -d ' ')
    echo "BACKUP_PATH=$newest_backup"
    echo "BACKUP_BYTES=$backup_bytes"
    echo "OK backup"
}

phase_incoming() {
    cd /opt/exposight
    git fetch origin main

    local commits
    commits=$(git log --oneline HEAD..origin/main)
    if [ -z "$commits" ]; then
        echo "NOTHING_TO_DEPLOY"
    else
        echo "Incoming commits:"
        git log --oneline HEAD..origin/main
        echo "Diff stat:"
        git diff --stat HEAD origin/main
    fi
    echo "OK incoming"
}

phase_pull() {
    cd /opt/exposight
    git pull --ff-only origin main
    local post_commit
    post_commit=$(git rev-parse HEAD 2>/dev/null || true)
    if [ -n "$post_commit" ]; then
        echo "POST_COMMIT=$post_commit"
    fi
    echo "OK pull"
}

phase_up() {
    cd /opt/exposight

    local up_started
    up_started=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "UP_STARTED=$up_started"

    local rc=0
    docker compose -f compose.prod.yml up -d --build --remove-orphans || rc=$?

    local migrate_id
    migrate_id=$(docker compose -f compose.prod.yml ps -qa migrate 2>/dev/null || true)
    local migrate_rc=""
    if [ -n "$migrate_id" ]; then
        migrate_rc=$(docker inspect "$migrate_id" --format '{{.State.ExitCode}}' 2>/dev/null || echo "1")
    else
        migrate_rc=1
    fi

    if [ "$migrate_rc" != "0" ]; then
        docker compose -f compose.prod.yml logs migrate
        echo "FAIL up: database migration failed (migrate container exit code $migrate_rc)" >&2
        exit 1
    elif [ "$rc" -ne 0 ]; then
        docker compose -f compose.prod.yml ps -a
        echo "FAIL up: docker compose up failed with code $rc" >&2
        exit "$rc"
    fi

    local alembic_rev
    alembic_rev=$(docker compose -f compose.prod.yml exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"' 2>/dev/null || true)
    if [ -z "$alembic_rev" ]; then
        echo "FAIL up: failed to query alembic_version from db container" >&2
        exit 1
    fi
    echo "POST_REVISION=$alembic_rev"

    docker compose -f compose.prod.yml up -d --force-recreate caddy

    local start_time
    start_time=$(date +%s)
    local timeout_secs=180
    local worker_restarted=0

    while true; do
        local worker_id
        worker_id=$(docker compose -f compose.prod.yml ps -q worker 2>/dev/null || true)
        if [ -n "$worker_id" ]; then
            local worker_state
            worker_state=$(docker inspect "$worker_id" --format '{{.State.Status}}' 2>/dev/null || true)
            if [ "$worker_state" = "created" ] && [ "$worker_restarted" -eq 0 ]; then
                echo "Worker container is in created state; restarting worker..."
                docker compose -f compose.prod.yml up -d worker
                worker_restarted=1
            fi
        fi

        local db_id egress_id api_id caddy_id
        db_id=$(docker compose -f compose.prod.yml ps -q db 2>/dev/null || true)
        egress_id=$(docker compose -f compose.prod.yml ps -q egress 2>/dev/null || true)
        api_id=$(docker compose -f compose.prod.yml ps -q api 2>/dev/null || true)
        caddy_id=$(docker compose -f compose.prod.yml ps -q caddy 2>/dev/null || true)

        local db_health="none" egress_health="none" api_health="none"
        local worker_status="none" caddy_status="none"

        if [ -n "$db_id" ]; then
            db_health=$(docker inspect "$db_id" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo "none")
        fi
        if [ -n "$egress_id" ]; then
            egress_health=$(docker inspect "$egress_id" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo "none")
        fi
        if [ -n "$api_id" ]; then
            api_health=$(docker inspect "$api_id" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo "none")
        fi
        if [ -n "$worker_id" ]; then
            worker_status=$(docker inspect "$worker_id" --format '{{.State.Status}}' 2>/dev/null || echo "none")
        fi
        if [ -n "$caddy_id" ]; then
            caddy_status=$(docker inspect "$caddy_id" --format '{{.State.Status}}' 2>/dev/null || echo "none")
        fi

        if [ "$db_health" = "healthy" ] && [ "$egress_health" = "healthy" ] && [ "$api_health" = "healthy" ] && [ "$worker_status" = "running" ] && [ "$caddy_status" = "running" ]; then
            break
        fi

        local now
        now=$(date +%s)
        local elapsed=$((now - start_time))
        if [ "$elapsed" -ge "$timeout_secs" ]; then
            docker compose -f compose.prod.yml ps
            echo "FAIL up: services timed out after ${timeout_secs}s waiting for healthy/running status (db=$db_health, egress=$egress_health, api=$api_health, worker=$worker_status, caddy=$caddy_status)" >&2
            exit 1
        fi

        sleep 2
    done

    echo "OK up"
}

phase_verify() {
    local since_time="${1:-}"
    cd /opt/exposight

    local egress_out
    egress_out=$(docker compose -f compose.prod.yml exec -T worker python - < scripts/egress_check.py 2>&1 || true)
    echo "$egress_out"

    local last_line
    last_line=$(printf '%s\n' "$egress_out" | awk 'NF { line = $0 } END { print line }')
    if [ "$last_line" != "egress check: PASSED" ]; then
        docker compose -f compose.prod.yml stop worker >/dev/null 2>&1 || true
        echo "FAIL verify: egress check failed ($last_line)" >&2
        exit 1
    fi

    local worker_logs
    if [ -n "$since_time" ]; then
        worker_logs=$(docker compose -f compose.prod.yml logs --since "$since_time" worker 2>&1 || true)
    else
        worker_logs=$(docker compose -f compose.prod.yml logs worker 2>&1 || true)
    fi

    if ! echo "$worker_logs" | grep -q "Starting ASM worker"; then
        echo "FAIL verify: worker log has no 'Starting ASM worker' line" >&2
        exit 1
    fi

    echo "OK verify"
}

case "${1:-}" in
    precheck)
        phase_precheck
        ;;
    backup)
        phase_backup
        ;;
    incoming)
        phase_incoming
        ;;
    pull)
        phase_pull
        ;;
    up)
        phase_up
        ;;
    verify)
        phase_verify "${2:-}"
        ;;
    *)
        usage
        ;;
esac

exit 0
