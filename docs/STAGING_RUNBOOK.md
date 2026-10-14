# Staging Validation Runbook: Exposight

This runbook defines the isolated deployment verification procedure for Exposight on a dedicated staging Linux VM. It establishes functional, security, and boundary checks for the merged codebase before any production release.

---

## 1. Prerequisites, Pricing & Resource Identity

### A. Subscription & Dedicated Host Requirement
Staging resources must be provisioned inside a dedicated, isolated Azure resource group on a dedicated virtual machine.
- **Target Resource Group:** `rg-exposight-staging` (tagged `Environment=staging`, `ManagedBy=deployer`).
- **Subscription Verification:** Verify the active Azure subscription ID via `az account show` before running any commands. Staging must never share a resource group with production assets.
- **Dedicated Staging Host VM Required:**
  - While Docker Compose project naming (`COMPOSE_PROJECT_NAME=exposight-staging`) isolates container, network, and volume names, it **does not** prevent host-level and subnet collisions.
  - `compose.prod.yml` defines a fixed bridge subnet (`10.89.0.0/24`) with static database IP `10.89.0.10`, and maps host ports `80` and `443` directly for Caddy.
  - Running staging on a host already running another stack using `compose.prod.yml` will fail due to subnet allocation overlap and port binding collisions. A separate, dedicated VM host is strictly required.
- **Pricing & Budget Notice:**
  - Resource costs depend on the deployed Azure region, active subscription offer type (e.g., Azure for Students, Pay-As-You-Go), and current regional pricing sheets.
  - Do NOT assume zero-cost or fixed generic estimates (e.g., "under $0.10"). Official regional retail pricing must be checked prior to provisioning:
    - Compute VM: `Standard_B2pts_v2` (ARM64) or `Standard_B1s` (AMD64).
    - Managed Disk: `StandardSSD_LRS` or `Standard_LRS` (specify exact SKU; do not use ambiguous labels).
    - Public IP: `Standard` SKU IPv4 address.
  - Compute charges accrue while the VM is in the `Running` state. Deallocating the VM (`az vm deallocate`) stops compute charges.

### B. Host Swap & Memory Sizing
- On low-memory virtual machines (1–2 GiB RAM), configure a 2 GiB swapfile (`/swapfile`).
- **Operational Reality:** Swap provides auxiliary virtual memory during burst allocations, but **does not guarantee** successful container builds or uninterrupted operation under sustained load or constrained burstable CPU credits. Disk I/O thrashing or OOM invocation remains possible if physical memory and swap are exhausted.

### C. Exact Commit, Build Identity & Pre-Build Checks
- **Base Commit & Pre-Build Source Check:**
  - An image tag alone does **not** prove which source code was actually built into a container image if the local working tree contains uncommitted edits or dirty files.
  - Before building images on staging, verify both the exact commit SHA and a clean working tree:
    ```bash
    git rev-parse HEAD
    git status --porcelain
    ```
    Assert the working tree is clean (or that any local staging configuration files are explicitly accounted for and reviewed).
- **Explicit Image Tagging (`IMAGE_TAG`):**
  - Staging images require an explicit `IMAGE_TAG` set to the verified commit SHA (e.g. `IMAGE_TAG=7c552b36928ae71a5d0052f1d600c4a68e3e2fab`).
  - `compose.staging.override.yml` strictly enforces this requirement (`${IMAGE_TAG:?IMAGE_TAG must be set...}`); silent fallback to stale default SHAs is disabled.
- **Image Configuration IDs vs. Manifest Digests:**
  - Tagged images built locally (e.g. `exposight-app:${IMAGE_TAG}`) receive a **local image configuration ID** (the SHA256 digest of the image's root JSON configuration structure):
    ```bash
    docker inspect --format='{{.Id}}' exposight-app:${IMAGE_TAG}
    ```
  - Image configuration IDs are distinct from **image manifest digests** (`@sha256:...`), which identify the OCI image manifest document rather than the image config blob. Ordinary version tags provide build traceability, but are neither image configuration IDs nor immutable manifest digests.
- Pinned third-party images (referenced in `compose.prod.yml` and Dockerfile):
  - `postgres:18.6-alpine`
  - `caddy:2.11.4-alpine`
  - `python:3.12.15-slim-trixie`

---

## 2. Configuration & Isolation Safeguards

### A. Staging Configuration Template
Copy `deploy/staging.env.example` to `.env` on the staging host:
```bash
cp deploy/staging.env.example .env
chmod 600 .env
```

### B. Deployment Designation vs. Application Mode
- `src/asm/config.py` enforces `VALID_ENVIRONMENTS = ("development", "test", "production")`.
- **"Staging" is an operational infrastructure designation, NOT an application mode.**
- `.env` must specify `ENVIRONMENT=production`. This activates full production guards:
  - Disables interactive API documentation (`/docs`, `/redoc`, `/openapi.json`).
  - Prohibits localhost/loopback database hosts and database names ending with `_test` (`src/asm/config.py`). Note: The `_test` restriction applies strictly to the database name (`url.database`), not the database host.
  - Mandates least-privilege non-superuser database roles (`APP_DB_USER`).
  - Restricts Uvicorn trusted reverse-proxy headers (`--forwarded-allow-ips=10.89.0.0/24`) to the configured `app-tier` bridge subnet (`10.89.0.0/24`), which allows any container on that network (not exclusively Caddy).
  - Rejects placeholder credentials.

### C. Discovery Limits & Staging Override
- `src/asm/discovery.py` enforces deterministic wire ingestion limits (`DEFAULT_MAX_RESPONSE_BYTES = 10 MiB`) and candidate hostname selection caps (`DEFAULT_MAX_HOSTS = 1000`).
- `compose.staging.override.yml` forwards `DISCOVERY_MAX_RESPONSE_BYTES` and `DISCOVERY_MAX_HOSTS` into the `worker` service environment.
- **Production Gap Follow-Up:** `compose.prod.yml` does not currently forward these two variables into `worker.environment`. In production, the hardcoded defaults in `src/asm/discovery.py` already bound resource consumption, so production is not unbounded. Updating `compose.prod.yml` to expose these variables is tracked as follow-up work.

### D. Identity & SaaS Project Isolation
- Create a dedicated Supabase project for staging (e.g., `exposight-staging`). Never reuse production or development credentials.
- Set JWT signing keys to ECC (`ES256`) or RSA (`RS256`); `src/asm/auth/token.py` strictly rejects legacy symmetric HS256 secrets.
- Configure Site URL (`https://<STAGING_DOMAIN>`) and Redirect URL (`https://<STAGING_DOMAIN>/app`).
- Set **Confirm email = ON** and **Allow new users to sign up = OFF** in Supabase Auth settings.

### E. Outbound Email Safety: Source-Verified Behavior & Controlled Sink
1. **Default Staging Safe Mode (`SMTP_HOST=""`):**
   - Source code in `src/asm/worker/worker.py` (lines 1553–1554) confirms:
     ```python
     if not self.smtp_host:
         return 0
     ```
   - When `SMTP_HOST` is unset or empty, `deliver_pending_alerts()` exits immediately without querying rows.
   - Generated outbox notifications remain safely in `status = 'pending'` in the `alert_notifications` table. They are **not retried, not failed, and not dispatched**.
2. **Drain & Batch Processing Behavior Upon Enabling SMTP:**
   - Setting `SMTP_HOST` does **not** cause an immediate unbounded flush. Instead, it makes pending notifications eligible for delivery under normal worker polling and batch/retry rules:
     - Worker polls for rows where `status = 'pending' AND next_attempt_at <= now()`.
     - Claims at most `batch_limit` (default 20) rows per cycle using `FOR UPDATE SKIP LOCKED`.
     - Evaluates daily domain alert quotas prior to sending.
   - Before enabling an active `SMTP_HOST`, operators must verify that all recipient addresses in `alert_notifications` belong to controlled test inboxes.
3. **Controlled Mail-Sink Architecture & Complete Worker Configuration:**
   - **Egress Firewall Constraint:** `deploy/egress/rules.sh` rejects all `10.0.0.0/8` traffic with `icmp-admin-prohibited`. An ordinary mail-sink container on the `app-tier` bridge network (`10.89.0.0/24`) cannot receive traffic from the worker.
   - **Loopback Namespace Sharing:** To permit controlled SMTP testing without weakening firewall rules, `compose.staging.override.yml` defines an opt-in `mailsink` container (`--profile mailsink`) with `network_mode: "service:egress"`. This places the sink in the egress network namespace on loopback (`127.0.0.1:1025`), where `iptables -A OUTPUT -o lo -j ACCEPT` allows delivery.
   - **Outbound Egress & Relay Notice:** Because the sink shares the egress network namespace, it shares whatever outbound network access is granted to that namespace (public internet and db:5432). Mailpit itself has outbound email relaying/forwarding **disabled** by default (no external SMTP relay host is configured), ensuring captured messages remain stored locally in-container.
   - **Profile Alone Does Not Reconfigure Worker:** Activating `--profile mailsink` starts the container but does **not** alter the worker's environment. The operator must explicitly configure worker SMTP variables in `.env`:
     ```env
     SMTP_HOST=127.0.0.1
     SMTP_PORT=1025
     SMTP_STARTTLS=false
     SMTP_SSL=false
     SMTP_USERNAME=
     SMTP_PASSWORD=
     SMTP_FROM=alerts@staging.yourdomain.invalid
     SMTP_TIMEOUT=10
     ```
4. **Sink Readiness Verification & Message Inspection Without Public UI Exposure:**
   - Verify `mailsink` is running and healthy inside the stack:
     ```bash
     docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml --profile mailsink ps mailsink
     ```
   - Verify sink API readiness from within the shared network namespace:
     ```bash
     docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml exec -T worker \
       python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/info').read().decode())"
     ```
   - **Private Inspection:** Because Mailpit binds to `127.0.0.1:8025` inside the egress container and publishes no external host ports, its web UI is not exposed to the public internet. Operators can inspect captured messages programmatically via the internal API:
     ```bash
     docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml exec -T worker \
       python -c "import urllib.request, json; res=json.loads(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages').read()); print(f'Total captured messages: {res[\"total\"]}')"
     ```

---

## 3. Staging Validation Protocol

### Offline Pre-Flight Verification
Prior to deploying or starting containers, run the offline verification suites locally:
1. **Discovery Limits & Logic Tests:**
   ```bash
   pytest tests/test_discovery.py -q
   ```
   *Expected:* 80 passed.
2. **Scan Detail Route Database Tests:**
   ```bash
   pytest tests/test_scan_detail_route_db.py -q
   ```
   *Prerequisite Notice:* These 6 route tests require a live, isolated test database (`TEST_DATABASE_URL=postgresql+psycopg://..._test`). When `TEST_DATABASE_URL` is unset, all 6 database-dependent tests are **skipped**.
3. **Deployment Configuration Tests:**
   ```bash
   pytest tests/test_deploy_config.py -q
   ```
   *Expected:* 18 passed.
4. **Compose Syntax & Interpolation Check:**
   When validating configuration files containing real staging credentials or tokens, **always use `--quiet`** to prevent credentials from being printed to the console or logs:
   ```bash
   docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml --env-file .env config --quiet
   ```

### Stage 1: Stack Startup & Migration Lifecycle
1. Start services using both base and staging override files:
   ```bash
   docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml up -d --build
   ```
2. Verify startup ordering and container health:
   ```bash
   docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml ps
   ```
   - `db` reports healthy (`pg_isready`).
   - `migrate` exits cleanly with code 0 (`alembic upgrade head`).
   - `api` reports healthy (`GET /health` returns 200).
   - `egress` reports healthy (rules applied, `/run/egress-ready` exists).
   - `worker` running with `network_mode: "service:egress"`.
   - `caddy` status is running (`Up`).
3. **Caddy Health vs. HTTPS Acceptance Check:**
   - Note: Caddy has **no Docker Compose healthcheck** defined in `compose.prod.yml`; a running container status does **not** prove ACME TLS certificate issuance or reverse-proxy readiness.
   - **Acceptance Check (Strict TLS Verification):**
     Execute without `-k`, requiring trusted certificate validation and HTTP 200:
     ```bash
     curl --fail --show-error https://<STAGING_DOMAIN>/health
     ```
     Assert HTTP 200 response with `{"status":"ok"}`.
   - **Separate Insecure TLS Diagnostics (Troubleshooting Only):**
     If certificate issuance fails during initial setup, inspect ACME challenges and handshake details using diagnostic-only commands (never used as an acceptance check):
     ```bash
     # Diagnostic only: inspect certificate chain
     openssl s_client -connect <STAGING_DOMAIN>:443 -servername <STAGING_DOMAIN> < /dev/null
     # Diagnostic only: bypass TLS verification to check basic upstream proxying
     curl -vk https://<STAGING_DOMAIN>/health
     ```

### Stage 2: Worker Egress Firewall Verification
Execute the automated egress verification script inside the worker:
```bash
docker compose -p exposight-staging -f compose.prod.yml -f compose.staging.override.yml exec -T worker python - < scripts/egress_check.py
```
- **Expected Results:**
  - `CONNECTED`: `db:5432`, `crt.sh:443`, `api.certspotter.com:443`, `1.1.1.1:443`.
  - `BLOCKED` (EHOSTUNREACH via `icmp-admin-prohibited`):
    - Cloud Metadata: `169.254.169.254:80`
    - Azure WireServer: `168.63.129.16:80`
    - Internal Services & Gateway: `api:8000`, `api:5432`, `10.89.0.1:22`, `10.0.0.1:22`
    - IPv6 public traffic: `2606:4700:4700::1111:443`
- **Negative Control Safety Rule:**
  - When verifying that a standard container without the egress firewall fails differently, **DO NOT** probe cloud metadata endpoints (`169.254.169.254` or `168.63.129.16`) from an unprotected container.
  - Restrict negative controls strictly to controlled test destinations (e.g. an unmapped port on an internal test IP or an isolated test server).

### Stage 3: Database Role Boundaries & Audit Immutability
1. Verify `api` and `worker` execute queries as `exposight_app`.
2. Connect to the staging database as `exposight_app` and verify privileges:
   - `SELECT` and `INSERT` on `audit_events` succeed.
   - `UPDATE`, `DELETE`, or `TRUNCATE` on `audit_events` fail with permission denied.
   - Attempting to drop the trigger `audit_events_append_only` fails with permission denied.

### Stage 4: Authentication, Permissions & Tenant Isolation
1. **User Onboarding:** Operator creates user accounts via Supabase Auth dashboard (`Auto Confirm User = checked`).
2. **Organization Creation:** Authenticate with an account listed in `ORG_CREATION_ALLOWED_EMAILS`; create `org-staging-alpha`. Authenticate with an unlisted account; assert `POST /orgs` returns `403 Forbidden`.
3. **Role Assignment & Tenant Separation:**
   - In `org-staging-alpha`, invite an Admin and a Viewer.
   - In `org-staging-beta`, create a separate organization.
   - Attempt cross-tenant reads: Viewer in `org-staging-alpha` requests `GET /ui/orgs/{org_staging_beta_id}/domains`; assert response is HTTP `404 Not Found` (anti-enumeration).

### Stage 5: Target Authorization & Scan Lifecycle
> **CRITICAL TARGET AUTHORIZATION RULE:**
> DNS TXT verification alone demonstrates control of a domain name, but does NOT grant authorization to perform active port scanning (`portscan`) or HTTP probing against third-party or shared hosting infrastructure.
> Staging active scans must be restricted to explicitly authorized, operator-owned target infrastructure (e.g. dedicated test hosts or isolated mock endpoints).

1. Add an authorized test domain to `org-staging-alpha`.
2. Perform DNS TXT verification (`_exposight-challenge.<domain>` containing `exposight-verify=<token>`). Assert public resolver verification succeeds.
3. Trigger manual scan (`POST /orgs/{org_id}/domains/{domain_id}/scans`).
4. Trace execution in worker logs:
   - `discover` $\rightarrow$ `probe` $\rightarrow$ `portscan` $\rightarrow$ `inspect` $\rightarrow$ `score`.
5. Verify scan status updates to `succeeded` with structured findings.

### Stage 6: Discovery Limits & Partial-Coverage UI Disclosure
1. **Deterministic Response-Byte Cap:** Verify discovery queries enforce `DISCOVERY_MAX_RESPONSE_BYTES` (default 10 MiB) before consuming excess response bytes.
2. **Deterministic Hostname Cap with Apex Prioritization:** Verify `DISCOVERY_MAX_HOSTS` (default 1,000) caps subdomains deterministically prior to active DNS resolution by prioritizing the observed apex domain (if present in discovered certificates) at index 0, followed by remaining subdomains sorted lexicographically (`src/asm/discovery.py:771-776`).
3. **UI Notice:** If a test domain discovery report has `truncated: true` and `truncation_reason` set, verify the scan detail UI renders the stage notice banner cleanly without CSP violations.

### Stage 7: Viewer Privacy & Breaking API Contract Verification
1. Authenticate as Organization Admin:
   - `GET /orgs/{org_id}/domains/{domain_id}` returns populated `alert_emails: ["admin@example.com"]` and `alert_recipient_count: 1`.
   - `GET /orgs/{org_id}/domains/{domain_id}/alert-notifications` returns populated `recipient: "admin@example.com"`.
2. Authenticate as Organization Viewer:
   - `GET /orgs/{org_id}/domains/{domain_id}` returns `alert_emails: null` and `alert_recipient_count: 1`.
   - `GET /orgs/{org_id}/domains/{domain_id}/alert-notifications` returns `recipient: null` and `last_error: null`.
3. Verify Dashboard UI:
   - Admin sees the recipient email chip list and save form.
   - Viewer sees `"1 recipient configured"`; recipient email list, input forms, and outbox recipient columns are completely absent.
4. **External API Impact Note:** The repository documents no external client integrations beyond `app.js`. However, the existence of private third-party scripts or downstream integrations is unknown. If external consumers exist, scripts parsing viewer `alert_emails` as an array will fail on `null`.

### Stage 8: Backup & Restore Drill
1. Execute backup script with an explicit dedicated staging directory:
   ```bash
   COMPOSE_PROJECT_NAME=exposight-staging ./scripts/backup_db.sh /var/backups/exposight-staging
   ```
   - Assert dump file created with mode 600, non-empty, and gzipped.
   - **Retention Pruning Notice:** `scripts/backup_db.sh` prunes backups older than 7 days (`find ... -mtime +6 -delete`). A dedicated staging directory (`/var/backups/exposight-staging`) must be used to prevent accidental deletion of backups from other environments or drills.
2. Restore drill into a temporary database:
   - Create temporary database `staging_restore_test`.
   - Restore using `psql --single-transaction`.
   - Assert tables, row counts, and Alembic migration version match live staging database.
   - Drop `staging_restore_test`.

---

## 4. Replay Acceptance Criteria: Open Release Blockers

Successful completion of the staging validation runbook provides operational and isolation evidence strictly within the tested staging scope and configuration. **It does NOT prove general operational reliability, defect absence, or satisfy/waive the three failed synthetic replay acceptance criteria:**
1. **False Changes:** 89.83 per 1,000 asset-scans (stop-rule threshold: $\le 1.0$) $\rightarrow$ **FAILED**.
2. **Alert-Eligible False Changes:** 0.85 per 1,000 asset-scans (stop-rule threshold: $\le 0.1$) $\rightarrow$ **FAILED**.
3. **Missed Real Events:** 1 missed event out of 180 (stop-rule threshold: $0$) $\rightarrow$ **FAILED**.

*Policy Requirement:* Production release remains blocked until an explicit product ownership decision either approves these measured noise tradeoffs or mandates additional detector revisions.

---

## 5. Teardown & Cleanup Protocol

> **CRITICAL TEARDOWN SAFEGUARD:**
> Cleanup is an explicitly separate, manual action. Never execute cleanup automatically or without interactive verification.

Before executing any deletion:
1. Verify the active subscription:
   ```bash
   az account show --query "{SubscriptionId:id, Name:name}" -o table
   ```
2. Verify that the target resource group is exclusively `rg-exposight-staging` and carries tag `Environment=staging`:
   ```bash
   az group show --name rg-exposight-staging --query "{Name:name, Tags:tags}" -o table
   ```
3. Confirm zero production or persistent resources are co-located.
4. With explicit operator authorization, execute teardown:
   ```bash
   az group delete --name rg-exposight-staging --yes --no-wait
   ```
