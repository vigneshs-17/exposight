# Production Deploy Pack: Exposight Next Release

**Target Commit SHA:** `169830d70851bec47469df0c088e24448381b9e7`  
**Target Release Branch:** `main`  
**Host Target:** `172.198.136.164` (ARM64 Ubuntu Linux VM)  
**Host Deploy Root:** `/opt/exposight`  
**Target Database Head Revision:** `0015_domain_subdomains_inventory`  

---

## 1. Release Overview & Included Changes

This deployment bundles all completed queue remediation milestones:
1. **Item 7 (Option 3 + Option A):** Accurate port alert semantics (`PORT_NEWLY_OPEN` alert-eligible only on new exposure or post-confirmed closure; `PORT_REOPENED` / `PORT_OBSERVED_OPEN` informational). Replay gates: 0.00/1k alert false changes, 0 misses.
2. **Item 8 (G5.2 Option A):** Viewer token redaction across API and UI partials (`verification_token` and `verification_record_value` set to `null` for viewers; DNS setup box hidden).
3. **Item 9 (G6 Ops Hardening):** Encrypted backup script (`scripts/backup_encrypted.sh`) with `age` public key validation and owner-only `077` umask; Caddy static IP `10.89.0.20` on `app-tier` and Uvicorn restricted to `--forwarded-allow-ips=10.89.0.20`; safe redirect targets in scanner prober.
4. **Item 10 (Third-Party Dependency Upgrades):**
   - Mailpit bumped to `v1.31.5` (PR #12)
   - Python base image bumped to `3.12.15-slim-trixie` (PR #13)
   - Caddy reverse proxy bumped to `2.11.7-alpine` (PR #14)
5. **Item 11 (Staging Validation):** Complete staging validation drill verified with zero drift (`alembic check`), append-only audit logs, multi-scan change detection, and Mailpit delivery.

---

## 2. Pre-Deploy Host Check & Fresh Backup

> **SSH Authentication Note:**
> Automated SSH attempts to `exposight@172.198.136.164` returned `Permission denied (publickey)`.
> The operator must execute the following deployment steps directly via their local authenticated terminal session.

### Step 1: Connect to VM
```bash
ssh -i ~/.ssh/exposight_ed25519 exposight@172.198.136.164
cd /opt/exposight
```

### Step 2: Pre-Deploy Health & Git Baseline
```bash
# Verify current checked-out commit
git rev-parse HEAD
git status --porcelain

# Verify running container status
docker compose -f compose.prod.yml ps

# Check current Alembic migration revision
docker compose -f compose.prod.yml exec -T db psql -U postgres -d asm -c "SELECT version_num FROM alembic_version;"
```

### Step 3: Run Fresh VM Database Backup
Execute unencrypted or encrypted backup prior to any code changes or migrations:
```bash
# Standard backup to /var/backups/exposight
sudo bash /opt/exposight/scripts/backup_db.sh /var/backups/exposight

# OR Encrypted backup (using the operator's age public recipient key)
sudo bash /opt/exposight/scripts/backup_encrypted.sh /var/backups/exposight "<AGE_RECIPIENT_KEY>"

# Verify the backup file was created and is non-empty
ls -lh /var/backups/exposight
```

---

## 3. Step-by-Step Deployment Procedure

### Step 4: Fetch & Checkout Target Commit
```bash
cd /opt/exposight
git fetch origin main
git checkout 169830d70851bec47469df0c088e24448381b9e7

# Verify clean state matching release SHA
assert_head=$(git rev-parse HEAD)
if [ "$assert_head" != "169830d70851bec47469df0c088e24448381b9e7" ]; then
    echo "ERROR: HEAD is at $assert_head, expected 169830d70851bec47469df0c088e24448381b9e7"
    exit 1
fi
```

### Step 5: Rebuild Application Container Images
```bash
export IMAGE_TAG=169830d70851bec47469df0c088e24448381b9e7
docker compose -f compose.prod.yml build
```

### Step 6: Apply Database Migrations (0001 -> 0015)
Run the migration container to apply pending schema changes up to `0015_domain_subdomains_inventory`:
```bash
docker compose -f compose.prod.yml run --rm migrate

# Verify database schema is at head
docker compose -f compose.prod.yml exec -T db psql -U postgres -d asm -c "SELECT version_num FROM alembic_version;"
```
*Expected output:* `0015_domain_subdomains_inventory`

### Step 7: Restart Application Stack
```bash
# Gracefully recreate API, worker, egress, and Caddy services
docker compose -f compose.prod.yml up -d --remove-orphans

# Check service status and healthchecks
docker compose -f compose.prod.yml ps
```
*Verify:*
- `db`: healthy
- `egress`: healthy
- `api`: healthy (`GET /health` returning 200)
- `worker`: running (attached to egress network)
- `caddy`: running

---

## 4. Post-Deploy Acceptance Verification

### Step 8: Health & Security Headers Check
Run from the VM or an external client:
```bash
# Health endpoint check
curl --fail --show-error https://<DOMAIN>/health

# Security headers inspection
curl -sI https://<DOMAIN>/health | grep -E -i "(strict-transport-security|content-security-policy|x-content-type-options|x-frame-options)"
```
*Verify:*
- Strict-Transport-Security: present
- Content-Security-Policy: present
- X-Content-Type-Options: `nosniff`
- X-Frame-Options: `DENY`

### Step 9: Worker & Egress Log Verification
```bash
# Check worker logs for successful initialization
docker compose -f compose.prod.yml logs --tail=50 worker

# Check API logs for proxy header forwarding
docker compose -f compose.prod.yml logs --tail=50 api
```

---

## 5. Rollback & Forward-Fix Policy

### Forward-Fix Policy:
Because migrations through `0015` add tables, columns, and indexes with backward-compatible defaults, small bug fixes should be pushed forward via standard CI and deployed immediately without schema downgrades.

### Emergency Database Rollback:
If database corruption or catastrophic failure occurs:
1. Stop application containers:
   ```bash
   docker compose -f compose.prod.yml stop api worker
   ```
2. Restore database from pre-deploy backup:
   ```bash
   # Standard backup restore
   gunzip -c /var/backups/exposight/<TIMESTAMP>_backup.sql.gz | docker compose -f compose.prod.yml exec -T db psql -U postgres -d asm --single-transaction
   
   # Encrypted backup restore
   age --decrypt -i ~/.ssh/exposight_backup_key /var/backups/exposight/<TIMESTAMP>_backup.sql.gz.age | gunzip -c | docker compose -f compose.prod.yml exec -T db psql -U postgres -d asm --single-transaction
   ```
3. Check out the previous stable git commit and restart services:
   ```bash
   git checkout <PREVIOUS_COMMIT>
   docker compose -f compose.prod.yml up -d
   ```
