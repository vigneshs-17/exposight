# Production Deployment Guide: Exposight

This guide documents deploying Exposight to a single **ARM64 Ubuntu Linux Virtual Machine** (such as an Oracle Cloud Always Free `VM.Standard.A1.Flex` instance — check Oracle's current Always Free limits in their docs before provisioning) using Docker Compose and Caddy.

---

## 1. Pinned Component Versions & Architecture

All third-party images and services used in production are pinned to specific immutable tags and architectures:

### Reverse Proxy & Ingress
- **Image**: `caddy:2.11.4-alpine` (latest Caddy release v2.11.4 at time of pinning; tag rebuilt by Docker Hub, so the tag is pinned, not the digest)
- **Supported Architectures**: `linux/amd64`, `linux/arm64`, `linux/arm/v7`, `linux/arm/v6`, `linux/ppc64le`, `linux/s390x`
- **Role**: Termination of TLS on ports 80/443, automatic Let's Encrypt / ZeroSSL HTTPS certificate provisioning via ACME, and reverse proxy to `api:8000`. Caddy adds only `Strict-Transport-Security` (the app does not set HSTS); it never overrides the application's CSP or other security headers.

### Database
- **Image**: `postgres:18.6-alpine`
- **Supported Architectures**: `linux/amd64`, `linux/arm64`
- **Role**: Relational store and append-only trigger-protected audit log (tenant isolation is enforced in application queries, not Postgres row-level security). Port 5432 is strictly bound to the internal `app-tier` Docker bridge network (`10.89.0.0/24`) and is never published to the host.

### Application & Worker
- **Base Image**: `python:3.12.14-slim-trixie`
- **Supported Architectures**: `linux/amd64`, `linux/arm64`
- **User**: Non-root system user `asm` (UID 10001, GID 10001).

---

## 2. Server Provisioning & OS Hardening

Before deploying Docker containers, perform basic host-level hardening on the Ubuntu VM:

### A. Non-Root Sudo User & SSH Key-Only Authentication
1. Log into the VM as root or default ubuntu user and create a dedicated deployer user:
   ```bash
   sudo adduser deployer
   sudo usermod -aG sudo deployer
   ```
2. Copy your public SSH key to `/home/deployer/.ssh/authorized_keys` and verify login:
   ```bash
   chmod 700 /home/deployer/.ssh
   chmod 600 /home/deployer/.ssh/authorized_keys
   ```
3. Disable SSH password authentication and root login in `/etc/ssh/sshd_config.d/50-cloud-init.conf` (or `/etc/ssh/sshd_config`):
   ```text
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   KbdInteractiveAuthentication no
   ```
4. Restart the SSH service:
   ```bash
   sudo systemctl restart ssh
   ```

### B. Automated Security Patches (Unattended Upgrades)
Install and enable automated security updates:
```bash
sudo apt update && sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```
Verify `/etc/apt/apt.conf.d/50unattended-upgrades` has `${distro_id}:${distro_codename}-security` enabled.

### C. Host Firewall (UFW / Oracle Cloud Security Lists)
Only SSH (port 22) and Web traffic (ports 80 and 443) should be reachable from the internet:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP (ACME / Redirect)'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw enable
```
*(Ensure ingress rules in Oracle Cloud VCN Security Lists match ports 22, 80, and 443).*

> **Oracle Ubuntu images:** they are known to ship their own host `iptables` rules that allow only SSH. If ports 80/443 stay closed after opening the Security List and UFW, inspect `sudo iptables -L INPUT -n --line-numbers` and the persisted rules in `/etc/iptables/rules.v4`. Verify against Oracle's current documentation.
>
> **Docker and UFW:** ports published by Docker bypass UFW rules. That is acceptable here only because the sole published ports are 80/443 (Caddy), which must be public anyway. Never publish db/api ports.

### D. Install Docker Engine + Compose plugin
1. Follow Docker's official guide for Ubuntu using the **apt repository** method: https://docs.docker.com/engine/install/ubuntu/ (it supports arm64).
2. Allow the deployer user to run Docker (membership of the `docker` group is equivalent to root on this host — keep it to this one user):
   ```bash
   sudo usermod -aG docker deployer
   ```
3. Log out and back in, then verify:
   ```bash
   docker version
   docker compose version
   ```

---

## 3. DNS Configuration

Exposight uses Caddy for automated TLS via ACME HTTP-01 challenges.

1. Create a DNS **A** record pointing to the public VM IP address:
   - Host: `@` (or subdomain, e.g. `exposight.dev`)
   - Value: `<VM_PUBLIC_IPV4_ADDRESS>`
2. **Cloudflare Note**: If using Cloudflare for DNS management, set the proxy status to **DNS-only** (grey cloud icon). Do NOT use Cloudflare Proxy (orange cloud), which intercepts HTTPS traffic and interferes with direct ACME challenge negotiation and origin CSP/header validation.

---

## 4. Production Secrets & Configuration

1. **Dedicated Production Supabase Project**:
   Create a completely separate Supabase project for production (never share development or staging Supabase credentials).
   Retrieve:
   - `SUPABASE_URL` (`https://<project-id>.supabase.co`)
   - `SUPABASE_PUBLISHABLE_KEY` (anon public key, e.g. `eyJ...`). Never set service_role keys.

2. **Clone and Configure**:
   ```bash
   git clone https://github.com/vigneshs-17/exposight.git /opt/exposight
   cd /opt/exposight
   cp .env.production.example .env
   chmod 600 .env
   ```

3. **Populate `.env`**:
   - Generate a strong random password for PostgreSQL:
     ```bash
     openssl rand -hex 24
     ```
   - Generate three different passwords: `POSTGRES_PASSWORD` (superuser), `OWNER_DB_PASSWORD` and `APP_DB_PASSWORD`. Put the owner password into `MIGRATION_DATABASE_URL` and the app password into `DATABASE_URL`. See "Least-privilege database roles" below.
   - Set `DOMAIN=exposight.dev`.
   - Set `ENVIRONMENT=production`. In this mode the api and worker **refuse to start** if `DATABASE_URL` points to a `_test` database or localhost, or still contains a placeholder, and the api also refuses a non-https or placeholder `SUPABASE_URL` and an empty or placeholder `SUPABASE_PUBLISHABLE_KEY`. Error messages name the setting, never its value. `/docs`, `/redoc` and `/openapi.json` are disabled. An unknown `ENVIRONMENT` value (for example `prod`) also stops startup.
   - Populate `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`.
   - Configure SMTP if outgoing email notification digests are desired (leave `SMTP_HOST` empty to disable email). Use `SMTP_STARTTLS=true` (port 587) **or** `SMTP_SSL=true` (implicit TLS, port 465), never both. Both verify the server certificate. If `SMTP_USERNAME`/`SMTP_PASSWORD` are set and neither TLS mode is enabled, the worker refuses to send and records a delivery error instead of sending credentials in clear text.

4. **Supabase Auth URLs (production project):** in the Supabase dashboard → Authentication → URL Configuration, set:
   - Site URL: `https://exposight.dev`
   - Redirect URLs: `https://exposight.dev/app` only (no `localhost` entries in the production project)
   - **Confirm email: must be ON** (Supabase docs: "This option can be found in the email provider under the provider-specific configuration"). Exposight invites (v3.6b) are accepted only when the signed-in user's email equals the invite email. Supabase access tokens carry no verified-email claim the API can trust (`user_metadata` is editable by the user), so the API relies on Supabase refusing sign-in until the email is confirmed. With Confirm email off, someone could sign up with another person's address and accept their invite.
   - Signups may stay open: a new account can see nothing until an org owner or admin invites it.

---

### Log redaction

The api, worker and admin CLI install a log filter (`src/asm/logredact.py`) that masks email addresses (`[email]`), secret-looking URL parameters such as `token=`, `code=` and `access_token=` (`[redacted]`), and JWT-shaped strings (`[jwt]`) in every log line, uvicorn's access log included. Delivery-failure log lines name the notification id, never the recipient. When debugging alert delivery, look up the recipient by notification id in the database instead of in the logs. PostgreSQL's own error log is not filtered: an error such as a unique-constraint violation can print the offending value. Caddy writes no access log (the `Caddyfile` has no `log` directive).

### Database downgrades

Downgrading migrations `0011` (organization invites), `0009` (the audit log), `0008` (domain verification state) or `0007` (domain ownership) permanently loses that data. Each of those downgrades refuses to run when its table has rows unless `ALLOW_DATA_LOSS_DOWNGRADE=1` is set. Take a backup first (`scripts/backup_db.sh`).

### Least-privilege database roles

Three PostgreSQL roles are used. None of the application processes runs as the superuser.

| Role | Used by | Privileges |
|---|---|---|
| `POSTGRES_USER` (superuser) | first-boot init, backups and restores only | everything |
| `OWNER_DB_USER` (`exposight_owner`) | `migrate` service (Alembic) | owns the database, every table, sequence and trigger; `NOSUPERUSER` |
| `APP_DB_USER` (`exposight_app`) | `api` and `worker` (`DATABASE_URL`) | owns nothing; `SELECT/INSERT/UPDATE/DELETE` on data tables; only `SELECT/INSERT` on `audit_events`; `NOSUPERUSER NOINHERIT` |

Because the app role does not own `audit_events`, it cannot `UPDATE`, `DELETE`, `TRUNCATE`, `ALTER TABLE ... DISABLE TRIGGER` or drop the append-only trigger (proved by `tests/test_db_roles_db.py`). Only the owner role can disable the trigger.

**Fresh volume (normal case):** `deploy/postgres-init/10-roles.sh` runs automatically the first time the `db` container starts with an empty `pgdata` volume. It creates both roles and makes the owner role the database owner. Migration `0010_app_role_grants` then grants the app role its privileges, including `ALTER DEFAULT PRIVILEGES FOR ROLE` the owner, so tables added by later migrations are granted automatically. With `ENVIRONMENT=production` the migration fails if the app role does not exist.

**Existing volume (manual runbook):** Docker only runs `docker-entrypoint-initdb.d` on an empty volume, so an already-initialised database needs these steps once. Back up first (`scripts/backup_db.sh`).

1. Open a superuser shell:
   ```bash
   docker compose -f compose.prod.yml exec db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"'
   ```
2. Create the roles (type the passwords at the prompts; nothing is stored in shell history):
   ```sql
   CREATE ROLE exposight_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   \password exposight_owner
   CREATE ROLE exposight_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
   \password exposight_app
   ```
3. Transfer ownership of the application tables to the owner role, then make it the database owner (replace `postgres` and `exposight` if your `POSTGRES_USER`/`POSTGRES_DB` differ):
   ```sql
   DO $$ DECLARE r record; BEGIN FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP EXECUTE format('ALTER TABLE public.%I OWNER TO exposight_owner', r.tablename); END LOOP; FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO exposight_owner', r.fn); END LOOP; END $$;
   ALTER DATABASE exposight OWNER TO exposight_owner;
   REVOKE ALL ON DATABASE exposight FROM PUBLIC;
   GRANT CONNECT, TEMPORARY ON DATABASE exposight TO exposight_owner;
   GRANT CONNECT ON DATABASE exposight TO exposight_app;
   ```
   The `DO` block moves every table (with its sequences) and function in `public`. `REASSIGN OWNED BY postgres` is not used because PostgreSQL refuses it for the bootstrap superuser, which also owns the system catalogs.
4. As the owner role (`SET ROLE exposight_owner;`), apply the app-role grants. If migration `0010` has not run yet, `alembic upgrade head` in the `migrate` service does this for you; otherwise run exactly the SQL from migration `0010`:
   ```sql
GRANT USAGE ON SCHEMA public TO exposight_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO exposight_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO exposight_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM exposight_app;
ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exposight_app;
ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO exposight_app;
   ```
5. Update `.env` with `OWNER_DB_*`, `APP_DB_*`, `MIGRATION_DATABASE_URL` and the new `DATABASE_URL`, then `docker compose -f compose.prod.yml up -d`.

## 5. Deployment & Release Management

### Single-Worker Architecture Note
In `compose.prod.yml`, the API service runs Uvicorn with `--workers 1`:
```yaml
command:
  - "asm.api.main:app"
  - "--host"
  - "0.0.0.0"
  - "--port"
  - "8000"
  - "--workers"
  - "1"
  - "--proxy-headers"
  - "--forwarded-allow-ips=10.89.0.0/24"
```
*Rationale*: request rate limits (60 requests/minute per user; 20/minute per IP for unauthenticated requests and failed sign-ins; `429` with `Retry-After`) are kept **in memory** in `src/asm/ratelimit.py`. Running several worker processes would give each its own counters and multiply the effective limit; that would need a shared store such as Redis, which is not used. Counters reset when the api restarts. The client IP comes from `X-Forwarded-For` only because uvicorn trusts that header from the Caddy subnet (`--forwarded-allow-ips=10.89.0.0/24`).

Quotas are counted in PostgreSQL and survive restarts: 10 domains per organization, 5 owned organizations per user (`403`), 3 manual scans per domain per hour (`429` with `Retry-After`), and 20 alert emails per domain per 24 hours (further alerts are delayed, not dropped).

Additionally, `--proxy-headers` and `--forwarded-allow-ips=10.89.0.0/24` ensure that Uvicorn trusts `X-Forwarded-For` and `X-Forwarded-Proto` only when delivered from Caddy running on the fixed `10.89.0.0/24` Docker network subnet, preventing spoofed IP injection by direct clients.

### Launching the Stack
```bash
docker compose -f compose.prod.yml up -d --build
```
Verify service health:
```bash
docker compose -f compose.prod.yml ps
```
The startup sequence:
1. `db` starts and reports healthy via `pg_isready`.
2. `migrate` runs `alembic upgrade head` and exits 0 (`service_completed_successfully`).
3. `api` starts and reports healthy via internal HTTP GET `/health`.
4. `worker` starts processing queued scans.
5. `caddy` starts once `api` is healthy, requests TLS certificate, and serves `https://exposight.dev`.

### Tag Releases & Rollbacks
Always deploy tagged Git releases in production:
1. **Tagging a release**:
   ```bash
   git tag -a v3.6.0 -m "Release v3.6.0"
   git push origin v3.6.0
   ```
2. **Deploying a release on the VM**:
   ```bash
   git fetch --tags
   git checkout v3.6.0
   docker compose -f compose.prod.yml up -d --build
   ```
3. **Rolling back** (to the previous release tag). If the newer release added a migration, downgrade it **first, while the newer code is still checked out** (the older tree does not contain the newer migration file):
   ```bash
   docker compose -f compose.prod.yml run --rm migrate downgrade <previous-revision>
   git checkout <previous-tag>
   docker compose -f compose.prod.yml up -d --build
   ```
   *(If a schema migration occurred, roll back the migration first using `docker compose -f compose.prod.yml run --rm migrate downgrade <revision>` — the migrate service's entrypoint is already `alembic`)*.

---

## 6. Database Backups, Off-Site Sync & Disaster Recovery

### Automated Daily Backups
The backup script at `scripts/backup_db.sh` runs `pg_dump` within the running database container, applies `umask 077` (owner-only permissions), compresses with gzip, and automatically deletes backups older than 7 days.

Configure a daily cron job:
```bash
sudo crontab -e
```
Add entry (runs at 03:00 UTC daily):
```cron
0 3 * * * /opt/exposight/scripts/backup_db.sh /var/backups/exposight >> /var/log/exposight_backup.log 2>&1
```

### Off-Site Backup Sync (Off-Host Storage)
Backups stored on the same VM will be lost if the instance is terminated or corrupted. Copy backup archives off the host to a remote server or local backup machine using `scp` / `rsync`:

Example off-site sync command (run from backup storage server or pull machine):
```bash
scp -i ~/.ssh/backup_key deployer@<VM_PUBLIC_IPV4_ADDRESS>:/var/backups/exposight/*.sql.gz /local/safe/backup/storage/
```

### Database Restore Procedure
In disaster recovery or database recreation:
0. Stop writers first so nothing changes during the restore:
   ```bash
   docker compose -f compose.prod.yml stop api worker
   ```
1. Identify the desired backup archive:
   ```bash
   ls -lt /var/backups/exposight/exposight_db_*.sql.gz
   ```
2. Decompress and pipe the SQL dump into PostgreSQL inside the database container:
   ```bash
   gunzip -c /var/backups/exposight/exposight_db_YYYYMMDD_HHMMSSZ.sql.gz | \
     docker compose -f compose.prod.yml exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"'
   ```
3. Verify restored data and run migrations check:
   ```bash
   docker compose -f compose.prod.yml run --rm migrate check
   docker compose -f compose.prod.yml start api worker
   ```

---

## 7. Updating & Logs

### Updating to a new release
```bash
cd /opt/exposight
scripts/backup_db.sh /var/backups/exposight   # always back up first
git fetch --tags
git checkout <new-tag>
docker compose -f compose.prod.yml up -d --build
docker compose -f compose.prod.yml ps
```

### Logs
```bash
docker compose -f compose.prod.yml logs -f --tail=100 api
docker compose -f compose.prod.yml logs -f --tail=100 worker
docker compose -f compose.prod.yml logs --tail=100 caddy   # certificate issuance problems show here
```
