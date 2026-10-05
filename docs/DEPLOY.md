# Production Deployment Guide: Exposight

This guide documents deploying Exposight to a single **ARM64 Ubuntu Linux Virtual Machine** (such as an Oracle Cloud Always Free `VM.Standard.A1.Flex` instance — check Oracle's current Always Free limits in their docs before provisioning) using Docker Compose and Caddy.

---

## 1. Pinned Component Versions & Architecture

All third-party images and services used in production are pinned to specific immutable tags and architectures:

### Reverse Proxy & Ingress
- **Image**: `caddy:2.11.4-alpine` (latest Caddy release v2.11.4 at time of pinning; tag rebuilt by Docker Hub, so the tag is pinned, not the digest)
- **Supported Architectures**: `linux/amd64`, `linux/arm64`, `linux/arm/v7`, `linux/arm/v6`, `linux/ppc64le`, `linux/s390x`
- **Role**: Termination of TLS on ports 80/443, automatic Let's Encrypt / ZeroSSL HTTPS certificate provisioning via ACME, and reverse proxy to `api:8000`. Caddy is configured strictly to forward traffic without overriding or injecting application CSP/HSTS security headers.

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
   - Update `POSTGRES_PASSWORD` and `DATABASE_URL` with this password.
   - Set `DOMAIN=exposight.dev`.
   - Set `ENVIRONMENT=production`.
   - Populate `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`.
   - Configure SMTP if outgoing email notification digests are desired (leave `SMTP_HOST` empty to disable email).

4. **Supabase Auth URLs (production project):** in the Supabase dashboard → Authentication → URL Configuration, set:
   - Site URL: `https://exposight.dev`
   - Redirect URLs: `https://exposight.dev/app` only (no `localhost` entries in the production project)
   - Signups: decided in v3.6b (planned: invite-only).

---

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
*Rationale*: Phase v3.6b implements in-memory per-IP rate limiting buckets. Running multiple worker processes without an external Redis instance would shard in-memory counters across processes, allowing clients to bypass rate quotas.

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
3. **Rolling back** (to the previous release tag):
   ```bash
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
