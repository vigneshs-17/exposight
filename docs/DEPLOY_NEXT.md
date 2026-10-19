# Production Deploy Pack: Exposight Next Release

| | |
|---|---|
| Target commit | `36248a3957774a0946931a184c955d7bd04fb34c` (`main`) |
| VM | Azure `Standard_B2als_v2` (2 vCPU, 4 GiB, **x86_64 / amd64**), `172.198.136.164`, user `exposight` |
| Deploy root | `/opt/exposight` |
| Expected DB head after deploy | `0015_domain_subdomains_inventory` |
| Last reported deploy | `2e886e2` (user-reported; schema before `0015`) |

The owner runs every command. Lines marked **VM** run in an SSH session on the VM, lines marked **Laptop** run in PowerShell on the laptop. Nothing here prints a secret: database commands use the `POSTGRES_USER` / `POSTGRES_DB` / `OWNER_DB_USER` / `APP_DB_USER` variables that already exist inside the `db` container (from the VM `.env` via `compose.prod.yml`).

## 1. What this release contains

Everything merged since `2e886e2`, including:
- Scanner and change-detection accuracy fixes (G3 inventory pruning, definite-DNS history, bootstrap, capacity ordering; port alert semantics Option 3 + Option A).
- Authorization hardening: worker verification-loss handling, last-active-owner guards, pre-delivery recheck of alert authorization, viewer redaction of verification tokens and operator reasons.
- Prober resource limits (no automatic decompression, 64 KB streaming cap), frontend org-switch/logout race guards.
- Ops: encrypted backup script, Uvicorn trusts forwarded headers only from Caddy `10.89.0.20`, Python `3.12.15-slim-trixie`, Caddy `2.11.7-alpine`.
- New public pages: `/.well-known/security.txt` and `/privacy`.
- **New migration `0015_domain_subdomains_inventory`** (new table `domain_subdomains`).
- IC-1 (fixes from the 2026-10-19 independent check, **no migration**): Python dependencies installed from the hashed lock `requirements/runtime.lock.txt`; GET and HEAD on `/` and `/health`; per-IP rate limit for every request without a verified identity; `/health` database check cached for 2 s; `Permissions-Policy` on every response; wider log redaction; stale JWKS keys served for at most 24 h; worker log `lease=` instead of `token=`; `/robots.txt`; Caddyfile drops `Via` and serves its own HTTP-to-HTTPS 308 without `Server`.

### 1.1 IC-1 deploy notes (added 2026-10-19)

- [ ] **Supabase auth settings (owner, dated 2026-10-19).** In the Supabase dashboard (Authentication → Sign In / Providers → Email), confirm **"Confirm email" is ON** and **"Allow new users to sign up" is OFF**, and write the date you checked into `STATUS.md`. Invite acceptance and the org-creation allowlist trust the email in the Supabase token; with "Confirm email" off, someone could sign up with another person's address (see `docs/DEPLOY.md`, Supabase section). Re-check after any change to the Supabase project.
- [ ] **Recreate Caddy after the pull.** The Caddyfile is a single-file bind mount; `git pull` replaces the file, and a running container keeps reading the old one. After `up -d --build` in section 3, run `docker compose -f compose.prod.yml up -d --force-recreate caddy`.
- [ ] **Check the new headers** (section 4.2): `curl -sI http://exposight.dev/` shows `308` with no `Server` line; `curl -sI https://exposight.dev/` shows `200` (HEAD now works), `Permissions-Policy: camera=(), microphone=(), geolocation=()`, and no `Via` line; `curl -s https://exposight.dev/robots.txt` shows `Disallow: /app`.

## 2. Pre-deploy

### 2.1 Connect and record the current state (VM)

```bash
ssh -i ~/.ssh/exposight_ed25519 exposight@172.198.136.164
cd /opt/exposight
git rev-parse HEAD | tee ~/pre-deploy-commit.txt      # the rollback commit
git status --porcelain                                # must print nothing
docker compose -f compose.prod.yml ps
docker compose -f compose.prod.yml exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"' \
  | tee ~/pre-deploy-revision.txt                     # expected: 0014_cancelled_scan_status
```

If `git status --porcelain` prints anything, stop: local edits on the VM would block `git pull --ff-only`. If `git branch --show-current` prints nothing (detached HEAD from an earlier `git checkout <sha>`), run `git checkout main` first.

### 2.2 Fresh backup (VM)

```bash
sudo bash scripts/backup_db.sh /var/backups/exposight
sudo chown -R exposight:exposight /var/backups/exposight
ls -lt /var/backups/exposight | head -3
```

The newest `exposight_db_<UTC timestamp>.sql.gz` must be non-empty. The script exits non-zero if the dump fails.

### 2.3 Copy the backup to the laptop (Laptop, PowerShell)

```powershell
$key = "$HOME\.ssh\exposight_ed25519"
$vm  = "exposight@172.198.136.164"
New-Item -ItemType Directory -Force D:\exposight-backups | Out-Null
$f = ssh -i $key $vm "ls -1t /var/backups/exposight/exposight_db_*.sql.gz | head -1"
scp -i $key "${vm}:$f" D:\exposight-backups\
Get-ChildItem D:\exposight-backups | Sort-Object LastWriteTime | Select-Object -Last 1
```

This file is an **unencrypted** database dump (emails, domains, scan results). Keep it on the laptop only; delete it once an encrypted backup routine (`docs/BACKUP_SETUP.md`) is running.

## 3. Deploy (VM)

```bash
cd /opt/exposight
git pull --ff-only origin main
git merge-base --is-ancestor 36248a3957774a0946931a184c955d7bd04fb34c HEAD && echo "target included"
git log --oneline -1
```

`git pull --ff-only` refuses to merge if the VM history diverged; stop and investigate instead of forcing. `HEAD` may be newer than `36248a3957774a0946931a184c955d7bd04fb34c` if only documentation was merged later; check with `git diff --stat 36248a3957774a0946931a184c955d7bd04fb34c HEAD` (only `docs/` or `*.md` lines are fine).

Build and start. The `migrate` service runs `alembic upgrade head` as the owner role; `api` and `worker` start only after it exits successfully:

```bash
docker compose -f compose.prod.yml up -d --build --remove-orphans
docker compose -f compose.prod.yml logs migrate
docker compose -f compose.prod.yml exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"'
docker compose -f compose.prod.yml ps
```

Expected:
- `migrate` logs end with `Running upgrade 0014_cancelled_scan_status -> 0015_domain_subdomains_inventory` and the container shows `Exited (0)`.
- `alembic_version` is `0015_domain_subdomains_inventory`.
- `db`, `egress`, `api` are `healthy`; `worker` and `caddy` are `running`.

If `migrate` exited non-zero, `api` and `worker` do not start. Read `docker compose -f compose.prod.yml logs migrate`, then go to section 5.

## 4. Post-deploy checks

### 4.1 Worker egress firewall (VM)

```bash
docker compose -f compose.prod.yml exec -T worker python - < scripts/egress_check.py | tail -1
```

Expected: `egress check: PASSED`. Anything else: run it without `| tail -1` to see which target failed, and stop the worker (`docker compose -f compose.prod.yml stop worker`) until it passes.

### 4.2 Health and security headers (Laptop or VM)

```bash
curl --fail --show-error https://exposight.dev/health
curl -sI https://exposight.dev/ | grep -i -E "strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|referrer-policy|^server"
curl -s https://exposight.dev/.well-known/security.txt
curl -s -o /dev/null -w "%{http_code}\n" https://exposight.dev/privacy
```

Expected: `/health` answers 200; HSTS, CSP (with `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` present; **no** `Server` header; `security.txt` shows `Contact`, `Expires`, `Preferred-Languages`, `Canonical`; `/privacy` answers 200. (On PowerShell use `curl.exe`, not the `curl` alias.)

### 4.3 Worker running (VM)

```bash
docker compose -f compose.prod.yml ps worker
docker compose -f compose.prod.yml logs --tail=30 worker
```

If the worker is not `running` (for example it stayed `Created` because `egress` was not healthy yet): `docker compose -f compose.prod.yml up -d worker`. Its log must show `Starting ASM worker`.

### 4.4 One manual scan (browser)

1. Sign in at `https://exposight.dev/app`.
2. Open the verified domain `exposight.dev` and click **Run scan** once.
3. Wait for the scan to finish (`succeeded`) and open it: subdomains, ports and HTTPS findings are listed. A first scan after `0015` bootstraps the new inventory from earlier scans; it must not report every known subdomain as new.
4. If it fails, read `docker compose -f compose.prod.yml logs --tail=100 worker`.

Scan only `exposight.dev` (a domain you own). Do not scan anything else during the check.

## 5. Rollback

Decide quickly: roll **forward** (fix and redeploy) for small bugs; roll **back** when the app is unusable or data looks wrong.

### 5.1 Code-only rollback (only if `migrate` did not apply `0015`)

If `alembic_version` still shows the pre-deploy revision (`~/pre-deploy-revision.txt`):

```bash
cd /opt/exposight
git checkout "$(cat ~/pre-deploy-commit.txt)"
docker compose -f compose.prod.yml up -d --build --remove-orphans
```

The previous images are rebuilt from the Docker layer cache, so this is fast. `git checkout <sha>` leaves a detached HEAD; return to `main` with `git checkout main` before the next deploy.

### 5.2 Full rollback after `0015` was applied: restore the pre-deploy backup

Old code cannot run against the new schema: its `migrate` service does not know revision `0015` and fails, so `api` and `worker` never start. **Do not try `alembic downgrade`:** the `0015` downgrade refuses on purpose when `domain_subdomains` contains rows (`refuse_lossy_downgrade`), which it does after the first scan. Restore the pre-deploy dump instead.

The dump must go into a **freshly recreated, empty database**, never on top of the existing tables.

1. Stop writers (VM):
   ```bash
   cd /opt/exposight
   docker compose -f compose.prod.yml stop api worker
   ```
2. Drop and recreate the database with the same owner and grants as `deploy/postgres-init/10-roles.sh` (VM). The roles survive; only the database is replaced:
   ```bash
   docker compose -f compose.prod.yml exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d template1 \
     -c "DROP DATABASE \"$POSTGRES_DB\" WITH (FORCE);" \
     -c "CREATE DATABASE \"$POSTGRES_DB\" OWNER \"$OWNER_DB_USER\";" \
     -c "REVOKE ALL ON DATABASE \"$POSTGRES_DB\" FROM PUBLIC;" \
     -c "GRANT CONNECT, TEMPORARY ON DATABASE \"$POSTGRES_DB\" TO \"$OWNER_DB_USER\";" \
     -c "GRANT CONNECT ON DATABASE \"$POSTGRES_DB\" TO \"$APP_DB_USER\";"'
   ```
3. Restore the newest pre-deploy dump in one transaction (VM):
   ```bash
   f=$(ls -1t /var/backups/exposight/exposight_db_*.sql.gz | head -1); echo "$f"
   gunzip -c "$f" | docker compose -f compose.prod.yml exec -T db sh -c \
     'psql -v ON_ERROR_STOP=1 --single-transaction -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
   docker compose -f compose.prod.yml exec -T db sh -c \
     'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"'
   ```
   Check that `$f` is the backup from step 2.2 (its timestamp is just before the deploy), not a later one. The revision must match `~/pre-deploy-revision.txt`. For an encrypted backup, decrypt on the laptop (`docs/BACKUP_SETUP.md`), copy the `.sql.gz` back with `scp`, and use it as `$f`.
4. Check out the previous commit and start it (VM):
   ```bash
   git checkout "$(cat ~/pre-deploy-commit.txt)"
   docker compose -f compose.prod.yml up -d --build --remove-orphans
   docker compose -f compose.prod.yml ps
   curl --fail --show-error https://exposight.dev/health
   ```
5. Run the egress check (4.1) again.

Data written between the backup and the rollback (scans, alerts, audit events) is lost. Drilled on 2026-10-19 against a local PostgreSQL 18.6 container with the production role layout: dump, drop/recreate, restore to `0015`, and app-role reads all succeeded.

## 6. After the deploy

- Record the deployed commit and the date in `STATUS.md` ("User-reported deployed behavior").
- Continue with the owner checklist: `docs/EMAIL_SETUP.md`, `docs/DNS_RECORDS.md`, `docs/BACKUP_SETUP.md`, `docs/MONITORING_SETUP.md`, `docs/DECISIONS_PENDING.md`.
