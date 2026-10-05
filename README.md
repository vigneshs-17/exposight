![CI](https://github.com/vigneshs-17/exposight/actions/workflows/ci.yml/badge.svg)

# Exposight - Attack Surface Management CLI

A lightweight, modular, and defensible Attack Surface Management (ASM) reconnaissance tool designed for cybersecurity engineers and students.

---

## Project Status

- **v1 CLI**: Done. 5-stage scanner (`discover`, `probe`, `portscan`, `inspect`, `score`).
- **v2.0.0 Service**: Done. API + database, job queue with crash recovery, Cert Spotter fallback, change detection, scheduled scans, and email alerts. See [CHANGELOG.md](CHANGELOG.md).
- **v3.1a User Auth & Organizations**: Done. Supabase JWT authentication, organization RBAC, and multi-tenant scoping.
- **v3.1b Tenant Isolation**: Done. Foreign keys, row-level organization fences, and anti-enumeration defenses.
- **v3.2 Domain Verification**: Done. Domain ownership proof via DNS TXT, continuous background re-verification, operator overrides, and scan gating.
- **v3.3 Audit Log & Event Tracking**: Done. Append-only audit events table, trigger against app tampering, 15 structured actions, and organization audit API.
- **v3.4a Dashboard Shell & Verification UI**: Done. Server-rendered dashboard (FastAPI + Jinja2 + HTMX), Supabase browser authentication, organization management, domains list, and DNS TXT verification UI.
- **v3.4b Scans, Results & Changes UI**: Done. Scans list (latest 20 runs, status, trigger, duration, changes summary), Run scan button (gated by domain verification and role), scan detail with 5 pipeline stages, Fix first prioritized findings (capped at 50 with overflow count), per-tier count cards, and changes table with auto-polling (3s, 15m cap).
- **v3.4c Schedule, Alerts & Audit Log UI**: Done. Domain schedule settings with presets (Off, 6h, 12h, 24h, 7 days, 30 days) and next scan time; email alerts settings (toggle, min severity, up to 5 recipients) with viewer email redaction; domain alert history outbox log with offset paging; and organization audit log with action/domain filtering, keyset pagination, and escaped metadata.
- **v3.4d Playwright Browser Tests**: Done. Real browser interaction tests in Chromium with live uvicorn server, route interception, 0 CSP violations, and multi-tenant UI verification.
- **Next: v3.5**: landing page.

---

## What It Does

`asm` operates in structured reconnaissance phases:

### Phase 1: Passive Subdomain Discovery (`asm discover`)
1. **Input Normalization & Validation**: Sanitizes target inputs (e.g. `http://EXAMPLE.COM:8080/path` -> `example.com`), verifies RFC compliance, and strictly rejects IP addresses and malformed domains.
2. **Certificate Transparency (CT) Discovery & Fallback**:
   - Queries `crt.sh` via its JSON API with resilient retry logic, backoff, and timeouts.
   - If `crt.sh` fails after its retry budget (e.g. 502, 404, or timeout), discovery automatically falls back to the **SSLMate Cert Spotter API** (`https://api.certspotter.com/v1/issuances`).
   - Supports optional `CERTSPOTTER_API_KEY` for higher rate limits (works without key within daily quotas).
   - Enforces bounded pagination (max 10 pages, 5,000 entries) and rate limit handling (`Retry-After <= 10s`).
   - Reports record discovery `source` (`"crt.sh"` or `"certspotter"`), sanitized `fallback_reason`, and `truncated` status.
3. **Data Hygiene & Deduplication**: Cleans wildcards (`*.example.com`), separates multi-line entries, discards out-of-scope hostnames and email addresses, and removes duplicates.
4. **Concurrent DNS Resolution**: Uses `dnspython` across a worker thread pool (max 20 workers) to resolve `A` (IPv4) and `AAAA` (IPv6) records for each discovered host.
5. **Deterministic Precedence Mapping**: Categorizes host statuses (`RESOLVED`, `NXDOMAIN`, `TIMEOUT`, `ERROR`, `NO_ANSWER`).
6. **Structured Reporting**: Exports results to a JSON file named `<domain>_<timestamp_utc>.json`.

### Phase 2: Active Host Probing (`asm probe`)
1. **Mandatory Authorization Gate**: Requires explicit `--authorized` confirmation before dispatching any network packets. (The local CLI is the operator's own tool; the hosted service requires DNS verification.)
2. **Untrusted Input Defense**: Re-validates every host from the input report against RFC standards and scope boundaries.
3. **SSRF Pre-Check**: Resolves hosts and blocks loopback, private, link-local, reserved, CGNAT (`100.64.0.0/10`), `0.0.0.0`, and IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) before issuing HTTP requests.
4. **Dual-Stack Default Port Probing**: Tests `https://<host>/` first (port 443), then `http://<host>/` (port 80).
5. **Strict Redirect Scope Enforcement**: Follows up to 5 in-scope redirects manually. Rejects external domains, non-default ports (e.g. 8080), or non-HTTP protocols.
6. **Defensive Streaming Body Cap**: Reads at most 64 KB of the response body to extract HTML `<title>` tags without downloading large files.
7. **End-to-End Deadline**: Enforces a strict 10.0-second total deadline per URL.
8. **TLS Certificate Fallback**: Flags invalid certificates (`tls_valid = False`), then retries once with `verify=False` solely to test service availability.

### Phase 3: Lightweight TCP Port Scanning (`asm portscan`)
1. **Mandatory Authorization Gate**: Requires `--authorized` confirmation before opening any socket connections.
2. **Fixed Default Port List Only**: Scans exactly 16 high-value common ports (no arbitrary ranges or intrusive full scans):
   - Ports: `21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`
3. **Asynchronous TCP Connect Scan**: Built with standard library `asyncio` (`open_connection`). No raw sockets, no SYN packets, and no kernel-level driver requirements.
4. **Strict State Classification**:
   - `OPEN`: Connection established.
   - `CLOSED`: Connection refused (`RST` received; host is up, port closed).
   - `FILTERED`: Connection timed out or dropped (firewall block).
5. **Non-Intrusive Banner Grabbing**:
   - For SSH (`port 22`): Listens passively (SSH servers speak first).
   - For `21, 25, 110, 143`: Sends a single `\r\n` CRLF prompt to trigger service greeting.
   - For all other ports: Listens passively for up to 2 seconds without sending payloads.
   - Sanitizes and truncates banners to at most 256 printable characters.
6. **Exposure Risk Flags**:
   - Database exposure (`3306`, `5432`, `6379`)
   - Remote access (`3389` RDP, `23` Telnet)
   - Windows file sharing (`445` SMB)
   - Legacy plaintext protocols (`21`, `23`, `25`, `110`, `143`)
7. **Politeness & Rate Limiting**: Capped at max 10 concurrent ports per host and max 5 hosts in parallel, with polite pacing delays between connections.

---

## Architecture

`asm` operates as a staged pipeline (`discover` -> `probe` -> `portscan` -> `inspect` -> `score`), where each stage reads the previous stage's JSON report, and active stages require `--authorized`. The local CLI is the operator's own tool; the hosted service requires DNS verification.

---

## Installation & Setup

### 1. Prerequisites
- Python 3.11 or higher
- PowerShell, Bash, or Command Prompt

### 2. Create and Activate a Virtual Environment
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Package with Development Tools
```bash
pip install -e ".[dev]"
```

---

## Run with Docker

Alternatively, run `asm` inside a containerized environment without installing Python or local dependencies.

### 1. Build the Docker Image
```bash
docker build -t asm-saas .
```

### 2. Run Commands Mounting the Local Output Directory
To persist generated reports to your host's `output/` directory, bind mount it to `/app/output`:

**Windows (PowerShell):**
```powershell
docker run --rm -v "${PWD}/output:/app/output" asm-saas discover example.com
```

**Linux / macOS:**
```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/output:/app/output" asm-saas discover example.com
```
> [!NOTE]
> On Linux and macOS, `--user "$(id -u):$(id -g)"` is required because the container runs as a non-root user (UID 10001) while mounted host directories retain host ownership, ensuring reports written to the host have correct write permissions.

> [!IMPORTANT]
> Active reconnaissance commands (`probe`, `portscan`, `inspect`) still require the mandatory `--authorized` flag inside the container:
> ```bash
> docker run --rm -v "${PWD}/output:/app/output" asm-saas probe output/<report>.json --authorized
> ```

---

## Run the API (v2, local only)

In v2, Exposight expands into a modular reconnaissance service featuring a FastAPI REST API backed by PostgreSQL and SQLAlchemy 2.0.

### 1. Environment Configuration
Create a local `.env` configuration file from the template:
```bash
cp .env.example .env
```
Ensure `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, and `DATABASE_URL` are defined in `.env`.
Optionally set `CERTSPOTTER_API_KEY` for Cert Spotter fallback (free tier works without a key within daily limits).

### 2. Start the Stack with Docker Compose
```bash
docker compose up --build
```
On startup:
1. `db`: Initializes the pinned `postgres:18.6-alpine` database service and waits until healthy.
2. `migrate`: Executes `alembic upgrade head` in a one-shot container to establish all tables (`domains`, `scan_runs`, `scan_results`).
3. `api`: Starts `uvicorn` serving the FastAPI application once migrations succeed.

### 3. Verify Health
The `/health` endpoint is public and requires no authentication:
```bash
curl -i http://127.0.0.1:8000/health
```
Response:
```json
{"status":"ok","database":"connected"}
```

---

### 4. Authentication, Organizations & Tenant Isolation (v3.1a, v3.1b)

All application API endpoints (except `/health`) require authentication via a valid Supabase JWT access token in the `Authorization: Bearer <token>` header, and are strictly scoped by organization under `/orgs/{org_id}/...`.

#### Role-Based Access Control (RBAC) Matrix

| Endpoint | Method | Min Role | Description |
|---|---|---|---|
| `/orgs/{org_id}/domains` | POST | `admin` | Register a new monitored domain |
| `/orgs/{org_id}/domains` | GET | `viewer` | List all domains belonging to this organization |
| `/orgs/{org_id}/domains/{domain_id}` | GET | `viewer` | Get domain details and schedule configuration |
| `/orgs/{org_id}/domains/{domain_id}/verification` | GET | `viewer` | Returns verification status and DNS TXT record instructions |
| `/orgs/{org_id}/domains/{domain_id}/verification/check` | POST | `admin` | Check DNS TXT record immediately (30s row-locked cooldown) |
| `/orgs/{org_id}/domains/{domain_id}/verification/rotate` | POST | `admin` | Generate new verification token and reset status to pending |
| `/orgs/{org_id}/domains/{domain_id}/scans` | POST | `admin` | Queue a reconnaissance scan for a verified domain |
| `/orgs/{org_id}/domains/{domain_id}/scans` | GET | `viewer` | List historical scans for a domain |
| `/orgs/{org_id}/scans` | GET | `viewer` | List all scans across the entire organization |
| `/orgs/{org_id}/scans/{scan_id}` | GET | `viewer` | Check scan status and pipeline stage progress |
| `/orgs/{org_id}/scans/{scan_id}/results/{stage}` | GET | `viewer` | Download raw stage JSON report |
| `/orgs/{org_id}/scans/{scan_id}/changes` | GET | `viewer` | List changes detected by a specific scan run |
| `/orgs/{org_id}/domains/{domain_id}/changes` | GET | `viewer` | List historical attack surface changes for a domain |
| `/orgs/{org_id}/domains/{domain_id}/schedule` | PUT | `admin` | Configure automated recurring scan schedule |
| `/orgs/{org_id}/domains/{domain_id}/alerts` | PUT | `admin` | Configure email alert recipients and minimum severity |
| `/orgs/{org_id}/domains/{domain_id}/alert-notifications` | GET | `viewer` | List alert delivery history |
| `/orgs/{org_id}/members` | GET | `viewer` | List members of the organization |
| `/orgs/{org_id}/members` | POST | `admin` | **410 Gone** since v3.6b: use invites |
| `/orgs/{org_id}/invites` | POST | `admin` | Create a single-use invite (`owner` only to invite owners); returns the token once |
| `/orgs/{org_id}/invites` | GET | `admin` | List pending invites (tokens never returned) |
| `/orgs/{org_id}/invites/{invite_id}` | DELETE | `admin` | Revoke a pending invite |
| `/invites/accept` | POST | any signed-in user | Accept an invite; the signed-in email must equal the invite email |
| `/orgs/{org_id}/members/{user_id}` | PATCH | `owner` | Update member role (enforces last-owner rule) |
| `/orgs/{org_id}/members/{user_id}` | DELETE | `owner` / self | Remove member or leave organization |
| `/orgs/{org_id}/audit-events` | GET | `admin` | List organization audit events with keyset cursor pagination |

#### Managing Organizations and Members
```bash
# 1. Create a new organization (creator automatically becomes 'owner')
curl -i -X POST http://127.0.0.1:8000/orgs \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Cybersecurity"}'

# 2. List organizations you belong to
curl -i http://127.0.0.1:8000/orgs \
  -H "Authorization: Bearer <token>"

# 3. List organization members
curl -i http://127.0.0.1:8000/orgs/1/members \
  -H "Authorization: Bearer <token>"

# 4. Invite someone (the response contains a one-time "token"; send it to them yourself).
#    The response is the same whether or not the email already has an account.
curl -i -X POST http://127.0.0.1:8000/orgs/1/invites \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "analyst@example.com", "role": "viewer"}'

# 4b. The invitee signs in with that email address and accepts (single use, expires in 7 days)
curl -i -X POST http://127.0.0.1:8000/invites/accept \
  -H "Authorization: Bearer <invitee-token>" \
  -H "Content-Type: application/json" \
  -d '{"token": "<invite-token>"}'

# 5. Update a member's role (owner only)
curl -i -X PATCH http://127.0.0.1:8000/orgs/1/members/<user-uuid> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# 6. Remove a member (owner only, or self-removal)
curl -i -X DELETE http://127.0.0.1:8000/orgs/1/members/<user-uuid> \
  -H "Authorization: Bearer <token>"
```

---

### 5. Managing Domains & Scans Under an Organization

#### Domain Ownership Verification Flow

To scan a domain on the hosted service, an organization must actively prove ownership via DNS TXT records.

##### Step 1: Register Target Domain (Status: `pending`)
Register a target domain within an organization (requires `admin` or `owner` role):
```bash
curl -i -X POST http://127.0.0.1:8000/orgs/1/domains \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com"}'
```
Response (HTTP 201 Created):
```json
{
  "id": 1,
  "org_id": 1,
  "name": "example.com",
  "verification_status": "pending",
  "verification_token": "k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "verification_method": "dns_txt",
  "verified_at": null,
  "last_checked_at": null,
  "consecutive_misses": 0,
  "verification_reason": null,
  "verification_expires_at": null,
  "scan_interval_hours": null,
  "next_scan_at": null,
  "alerts_enabled": false,
  "alert_emails": [],
  "alert_min_severity": "MEDIUM",
  "created_at": "2026-10-02T08:00:00Z",
  "verification_record_name": "_asm-verify.example.com",
  "verification_record_type": "TXT",
  "verification_record_value": "asm-verify=k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "is_verified": false
}
```

##### Step 2: Retrieve Verification Instructions
Inspect the domain's verification posture and exact DNS record requirements:
```bash
curl -i http://127.0.0.1:8000/orgs/1/domains/1/verification \
  -H "Authorization: Bearer <token>"
```
Response:
```json
{
  "domain_id": 1,
  "domain_name": "example.com",
  "status": "pending",
  "method": "dns_txt",
  "token": "k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "record_name": "_asm-verify.example.com",
  "record_type": "TXT",
  "record_value": "asm-verify=k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "verified_at": null,
  "last_checked_at": null,
  "consecutive_misses": 0,
  "verification_reason": null,
  "verification_expires_at": null,
  "is_verified": false,
  "check_outcome": null,
  "check_detail": null
}
```

##### Step 3: Add DNS TXT Record
Publish the TXT record in your authoritative DNS zone:
- **Host / Name**: `_asm-verify.example.com`
- **Type**: `TXT`
- **Value**: `asm-verify=k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO`

##### Step 4: Verify DNS Record
Trigger immediate DNS verification check (requires `admin` or `owner` role; rate-limited with a 30s cooldown):
```bash
curl -i -X POST http://127.0.0.1:8000/orgs/1/domains/1/verification/check \
  -H "Authorization: Bearer <token>"
```
Response (HTTP 200 OK):
```json
{
  "domain_id": 1,
  "domain_name": "example.com",
  "status": "verified",
  "method": "dns_txt",
  "token": "k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "record_name": "_asm-verify.example.com",
  "record_type": "TXT",
  "record_value": "asm-verify=k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO",
  "verified_at": "2026-10-02T08:05:00Z",
  "last_checked_at": "2026-10-02T08:05:00Z",
  "consecutive_misses": 0,
  "verification_reason": null,
  "verification_expires_at": null,
  "is_verified": true,
  "check_outcome": "match",
  "check_detail": "Exact TXT record match verified"
}
```

##### Step 5: Queue and Track Asynchronous Scans
Once `is_verified: true`, scans and schedules are permitted. Background workers process scans asynchronously using PostgreSQL `FOR UPDATE SKIP LOCKED`.

```bash
# Queue a scan for a verified domain (returns 202 Accepted)
curl -i -X POST http://127.0.0.1:8000/orgs/1/domains/1/scans \
  -H "Authorization: Bearer <token>" \
  -H "Idempotency-Key: optional-uuid-token"

# Check scan status and stage progress
curl -i http://127.0.0.1:8000/orgs/1/scans/1 \
  -H "Authorization: Bearer <token>"

# Download raw stage JSON report
curl -i http://127.0.0.1:8000/orgs/1/scans/1/results/score \
  -H "Authorization: Bearer <token>"

# List all scans across the organization
curl -i http://127.0.0.1:8000/orgs/1/scans \
  -H "Authorization: Bearer <token>"

# List historical scans for a specific domain
curl -i "http://127.0.0.1:8000/orgs/1/domains/1/scans?status=succeeded&limit=10" \
  -H "Authorization: Bearer <token>"
```

#### Attack Surface Changes
```bash
# Query changes detected for a domain (newest first)
curl -i http://127.0.0.1:8000/orgs/1/domains/1/changes \
  -H "Authorization: Bearer <token>"

# Filtered by severity, category, or type
curl -i "http://127.0.0.1:8000/orgs/1/domains/1/changes?severity=CRITICAL" \
  -H "Authorization: Bearer <token>"
curl -i "http://127.0.0.1:8000/orgs/1/domains/1/changes?change_type=PORT_NEWLY_OPEN&limit=10" \
  -H "Authorization: Bearer <token>"

# Query changes detected in a single scan run
curl -i http://127.0.0.1:8000/orgs/1/scans/2/changes \
  -H "Authorization: Bearer <token>"
```

#### Recurring Scan Scheduling & Alerts
```bash
# Enable 24-hour recurring scans
curl -i -X PUT http://127.0.0.1:8000/orgs/1/domains/1/schedule \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"interval_hours": 24}'

# Disable recurring scans
curl -i -X PUT http://127.0.0.1:8000/orgs/1/domains/1/schedule \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"interval_hours": null}'

# Configure email alerts
curl -i -X PUT http://127.0.0.1:8000/orgs/1/domains/1/alerts \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "alerts_enabled": true,
    "alert_emails": ["security@example.com", "ops@example.com"],
    "alert_min_severity": "HIGH"
  }'

# Query alert notification history
curl -i http://127.0.0.1:8000/orgs/1/domains/1/alert-notifications \
  -H "Authorization: Bearer <token>"
```

---

### 6. Audit Log (v3.3)

The ASM platform maintains an append-only audit trail recording state-changing actions performed by users, operators, and background system workers. The audit log is append-only against the application; the table owner can disable the trigger.

#### Audit Actions (15 Actions)

| Action | Actor | When |
|---|---|---|
| `org.created` | `user` | An organization is created via API |
| `membership.added` | `user` | A member is added to an organization |
| `membership.role_changed` | `user` | A member's role is updated |
| `membership.removed` | `user` | A member is removed or leaves an organization |
| `domain.created` | `user` | A domain is registered within an organization |
| `domain.schedule_changed` | `user` | Domain recurring scan schedule is updated or disabled |
| `domain.alerts_changed` | `user` | Domain email alert settings are configured |
| `verification.checked` | `user` | Immediate DNS TXT verification check is triggered |
| `verification.rotated` | `user` | Verification token is regenerated and status reset to pending |
| `verification.operator_granted` | `operator` | Operator grants break-glass verification override via CLI |
| `verification.operator_revoked` | `operator` | Operator revokes verification override via CLI |
| `verification.lapsed` | `system` | Background worker lapses domain after 2 consecutive DNS misses |
| `verification.override_expired` | `system` | Background worker expires operator override past validity window |
| `domain.moved` | `operator` | Operator moves a domain from legacy quarantine to an organization |
| `scan.queued` | `user` | A manual scan run is queued via API |

#### Security & Privacy Invariants
- **What is not recorded:** Denied requests (HTTP 401, 403, 404, 422), client IP addresses, user agents, and user login events are never recorded in `audit_events`.
- **Metadata hygiene:** Metadata strictly uses a fixed allowlist of keys and data types per action. Audit events never store verification tokens, JWTs, email addresses, or IP addresses.
- **Free-text redaction & truncation:** Free-text values (organization name, operator reasons) are truncated to at most 500 characters, and email addresses or IP address patterns are masked as `[redacted]`.
- **Payload size cap:** Serialized event metadata is hard-capped at 2048 bytes.

#### Querying Organization Audit Events
Audit events are scoped strictly to the organization and accessible only to `admin` and `owner` roles (`viewer` receives HTTP 403 Forbidden; non-members receive HTTP 404 Not Found to prevent tenant enumeration):
- **Filters:** `domain_id` (filters domain-scoped events) and `action` (filters by exact action name).
- **Pagination & Ordering:** Results are returned newest first (`id DESC`). Keyset cursor pagination uses `before_id` (returns events with `id < before_id`) and `limit` (default 50, maximum 100).

```bash
# Query audit trail with filters and keyset cursor pagination
curl -i "http://127.0.0.1:8000/orgs/1/audit-events?domain_id=1&action=verification.checked&limit=50&before_id=100" \
  -H "Authorization: Bearer <token>"
```

---

### 7. Dashboard (v3.4a-v3.4c)

A lightweight, server-rendered web dashboard built using FastAPI, Jinja2 templates, and HTMX with zero node/npm build dependencies.

#### How to Run
1. Set `SUPABASE_PUBLISHABLE_KEY` (public, non-secret client key) in `.env`:
   ```bash
   SUPABASE_PUBLISHABLE_KEY=your-supabase-publishable-key
   ```
2. Start the API service:
   ```bash
   docker compose up -d api
   ```
3. Open `http://127.0.0.1:8000/app` in your browser.

#### What Works
- **Sign-in:** Browser signs in directly via Supabase Auth using `supabase-js`. The user password goes only to Supabase and never touches application server memory.
- **Organization Switcher:** Switch between active organizations from the top navigation bar.
- **Create Organization:** New users without an organization are presented with a creation screen to establish their first organization.
- **Domains List:** View all monitored domains for the selected organization with status badges and verification states.
- **Add Domain:** Monitored root domain registration form (visible to `admin` and `owner` roles).
- **Domain Verification Page:** Full DNS TXT proof-of-control inspection view including:
  - Verification host record name and value with one-click clipboard copy buttons.
  - "Check now" button displaying real-time check outcome (`match`, `absent`, `unknown`) and detailed failure reason.
  - "Rotate token" button (with confirmation modal) to generate a fresh token if an existing record is compromised.
- **Role-Based Views:** Users with the `viewer` role see a read-only interface; write forms and state mutation buttons are omitted from the rendered DOM (and writes remain enforced by the API).
- **Scans List:** Latest 20 runs for the selected domain with status, trigger, started at timestamp, duration, and a change summary (`Baseline scan`, `No changes`, or tier counts like `1 critical, 2 info`).
- **Run Scan:** Gated to `admin` and `owner` roles. When the domain is unverified, the button is disabled with a visible reason: `"Domain ownership verification required to run scans."`
- **Scan Detail:** Inspection panel featuring:
  - 5 pipeline stages (`discover`, `probe`, `portscan`, `inspect`, `score`) with stage status badges, execution durations, and error descriptions.
  - Fix first: Prioritized security findings sorted by severity tier (`Critical` > `High` > `Medium` > `Low` > `Info`), score points descending, target host ascending, and port ascending (`None` precedes numeric ports). Capped at 50 rows with an overflow count: `"... and N more findings."`
  - Per-tier count cards: Summary cards for Domain score, Risk band, Critical, High, Medium, and Low counts (calculated across all parsed findings before capping).
  - Changes table: Structured delta entries from `ScanChange` records displaying severity, category, change type, asset, detail, and evidence (or `"No changes detected in this scan."`).
- **Real-Time Polling & Cap:** Scans in `queued` or `running` state poll `/ui/orgs/{org_id}/scans/{scan_id}` every 3 seconds via HTMX (`hx-trigger="every 3s"`, `hx-target="this"`, `hx-swap="outerHTML"`). Polling is capped at 15 minutes from `created_at`; after that, polling stops and displays a banner: `"Still <status> after 15 minutes. Automatic updates have stopped."` alongside a manual `"Refresh"` button. Finished scans omit polling attributes entirely to prevent unintentional re-fetching on user clicks.
- **Schedule:** Presets `Off`, `Every 6 hours`, `Every 12 hours`, `Every 24 hours`, `Every 7 days`, `Every 30 days`, and next scan time. On unverified domains, only "Off" is enabled to allow turning off background scans; cadence presets are disabled with `"Domain ownership verification required before scheduling automated scans."`
- **Alerts:** Enable toggle, minimum severity selector, and dynamic email chip input supporting up to 5 recipients. On unverified domains, alerts cannot be enabled (`"Domain ownership verification required before enabling alerts."`), but can be disabled. Viewers see only the recipient count (`"N recipients configured"`), never recipient email strings.
- **Alert History:** Outbox log for domain email notifications with offset pagination (`Previous` / `Next`, 50 per page) and collapsible message body inspection (`"View message body"`). The `Recipient` and `Last error` columns are displayed to `admin` and `owner` roles only, preventing raw SMTP exception text from exposing recipient emails to viewers.
- **Audit Log:** Organization-wide append-only audit trail restricted to `admin` and `owner` roles. Filterable by lifecycle action (`All actions` dropdown) and target domain (`All domains` dropdown). Keyset cursor pagination using `"Older events"` (`before_id`) and `"Newest"` controls. Event metadata is serialized to a standard string and rendered as escaped JSON in `<pre><code>` blocks.

#### Security Design
- **All Writes Reuse the Existing JSON API:** The dashboard introduces zero new write endpoints and no duplicated business logic. Form submissions and action triggers dispatch `fetch()` requests directly to `/orgs`, `/orgs/{org_id}/domains`, `/orgs/{org_id}/domains/{domain_id}/verification/*`, and `/orgs/{org_id}/domains/{domain_id}/scans`, then refresh DOM fragments via `htmx.ajax()`.
- **Bearer Token Authorization:** Every HTMX request and `fetch()` call attaches `Authorization: Bearer <access_token>` synchronously via `htmx:configRequest`. This is inherently immune to Cross-Site Request Forgery (CSRF).
- **XSS Mitigation Trade-off:** Storing access tokens in browser memory introduces potential XSS exposure if malicious JavaScript executes. This risk is defended through layered controls:
  - Strict Content Security Policy (CSP) on `/app`, `/ui/*`, and `/static/*`: `default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' <SUPABASE_URL>; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.
  - Zero inline `<script>` tags, zero inline `<style>` tags, and zero inline HTML event handlers.
  - `htmx.config.allowEval = false` and `htmx.config.allowScriptTags = false` configured in JS and via `<meta name="htmx-config">`.
  - Jinja autoescape enabled on all templates.
  - API responses rendered dynamically via `textContent` only; zero occurrences of `innerHTML`.
- **Attacker-Influenced Evidence & Change Fields:** Finding evidence, why-it-matters strings, titles, change assets, details, and error descriptions are attacker-influenced data derived from network scans and DNS records. They are rendered exclusively as HTML-escaped text in `<code>` blocks and standard markup, never as active links (`<a href>`) or raw unescaped HTML (`|safe`).
- **Template CSP Guard Test:** A dedicated test (`test_templates_have_no_csp_blocked_inline_code`) validates all Jinja2 templates on disk, failing the build if any template contains an inline `style` attribute, `<style>` block, inline event handler (`on*=`), HTMX eval handler (`hx-on`), or inline `<script>` tag.
- **Cache Invalidation:** `Cache-Control: no-store` header is enforced on all `/ui/*` HTML fragment responses to prevent caching sensitive tenant data.
- **Session Storage:** Tokens are held in module memory and backed by `sessionStorage` (cleared when the browser tab closes, never persisted to `localStorage`).
- **Vendored Libraries:** HTMX `2.0.11` and Supabase JS `2.117.2` UMD builds are vendored locally with pinned versions, official upstream URLs, and cryptographic SHA-256 checksums documented in `src/asm/static/vendor/VENDOR.md`.

#### Browser tests (v3.4d)

End-to-end browser integration tests executed with Playwright in headless Chromium against an in-process Uvicorn server thread on an ephemeral port.

##### What They Cover
1. `test_browser_signin_and_domain_inventory`: Browser sign-in via form, `#app-shell` visibility, domain listing, and zero CSP violations.
2. `test_browser_viewer_rbac_privacy`: Viewer role sees recipient count, write forms omitted, and no email addresses anywhere in DOM or alert history.
3. `test_browser_schedule_unverified_domain`: Unverified domain allows only "Off" schedule preset, displays verification notice, and persists setting.
4. `test_browser_email_chips_interaction`: Recipient chip additions, removal, case-insensitive duplicate rejection, and 5-chip cap enforcement.
5. `test_browser_alerts_save_decision_a`: On unverified domain, enabling alerts returns 422, while disabling alerts succeeds (Decision A).
6. `test_browser_scan_detail_polling_lifecycle`: Scan polling auto-refreshes every 3 seconds via HTMX and cleans up polling attributes upon completion.
7. `test_browser_401_retry_preserves_single_container`: Token refresh on 401 retries scan poller preserving single `#scan-detail-container` without nesting.
8. `test_browser_audit_log_filters_and_paging`: Audit log keyset pagination (50 on page 1, 5 on page 2, return to newest) and action filtering.
9. `test_browser_production_app_rejects_fake_token_401`: Verifies production auth dependency rejects synthetic test JWT tokens with HTTP 401.
10. `test_browser_check_now_result_stays_visible`: Verification "Check now" outcome box persists in DOM after network settle.

##### How to Run (Windows PowerShell)
```powershell
.\.venv\Scripts\pip install -e ".[dev]"
.\.venv\Scripts\playwright install chromium
docker start asm-test-db
$env:TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5433/asm_test"
.\.venv\Scripts\pytest -m browser -v
```

##### Test Execution & CI Isolation
- **Deselected by Default Locally:** `pyproject.toml` configures `addopts = "-v --strict-markers -m 'not integration and not browser'"`, preventing browser tests from running during routine unit test runs.
- **Separate CI Job:** Browser tests run in their own GitHub Actions job (`browser-test` in `.github/workflows/ci.yml`) using a dedicated PostgreSQL service container, installing Playwright system dependencies with `playwright install --with-deps chromium`, and uploading trace/screenshot artifacts on failure.
- **Security Invariant:** Zero test-only authentication pathways or backdoors exist in application code (`src/`). Synthetic tokens, token registries, and Supabase auth endpoint interception exist exclusively inside `tests/browser/`. If a synthetic test token is sent to the application without test overrides, the real production auth verifier rejects it with HTTP 401 (proven by `test_browser_production_app_rejects_fake_token_401`).

---

### 8. Admin CLI: Migrating Quarantine Domains

Migration `0007_tenant_isolation` safely moved pre-existing unscoped domains into an isolated organization with `system_kind = 'legacy_quarantine'` (with zero members, rendering it inaccessible to all normal users).

To move a quarantined domain into a customer organization, administrators use the CLI tool:
```bash
python -m asm admin move-domain --domain-id <domain_id> --target-org-id <target_org_id>
```
Security invariants enforced:
- **Refuses Non-Quarantine Domains:** Exits with code 1 if the domain's current organization is not `system_kind = 'legacy_quarantine'`.
- **Target Organization Validation:** Exits with code 1 if `target_org_id` does not exist or is itself a quarantine organization.
- **Per-Org Name Collision Check:** Exits with code 1 if the target organization already monitors that domain name.


### 9. Local Database Testing Setup & Migrations

#### How the Test Suite Creates the Database Schema
The pytest integration test suite (`pytest -m db`) creates its database schema programmatically via SQLAlchemy:
- When running tests, the session-scoped fixture `db_engine` in `tests/conftest.py` connects to `TEST_DATABASE_URL` (after validating that the database name ends with `_test` for safety).
- It executes `Base.metadata.create_all(bind=engine)`, ensuring all tables, columns, indexes, and constraints defined across `src/asm/db/models.py` exist before tests execute.
- Per-test isolation is maintained via savepoint transactions (`join_transaction_mode="create_savepoint"`), rolling back all changes after each test.

#### Migration Testing in CI (`db-test` Job)
To verify that Alembic migration scripts remain in 100% synchronization with SQLAlchemy ORM models, the CI `db-test` workflow executes a strict 4-step verification sequence against PostgreSQL:
```bash
# 1. Apply all migrations up to head
alembic upgrade head

# 2. Check for schema drift between models.py and migrations (fails if diff exists)
alembic check

# 3. Verify reversible downgrade functionality
alembic downgrade -1

# 4. Re-apply to head for test execution
alembic upgrade head
```

#### Running Database Tests Locally
To run the database integration test suite locally against a dedicated throwaway PostgreSQL 18 container:

1. Start a throwaway PostgreSQL container named `asm-test-db` on port `5433`:
   ```bash
   docker run -d --name asm-test-db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=asm_test -p 127.0.0.1:5433:5432 postgres:18.6-alpine
   ```

2. Run the Alembic migration verification cycle:
   ```bash
   # Windows (PowerShell)
   $env:DATABASE_URL = "postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   alembic upgrade head
   alembic check
   alembic downgrade -1
   alembic upgrade head

   # Linux / macOS
   export DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   alembic upgrade head
   alembic check
   alembic downgrade -1
   alembic upgrade head
   ```

3. Set `TEST_DATABASE_URL` (safety check: the database name must end with `_test`) and run tests:
   ```bash
   # Windows (PowerShell)
   $env:TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   pytest -m db

   # Linux / macOS
   TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test" pytest -m db
   ```




## Usage

### 1. Discover Subdomains (Passive)
```bash
asm discover example.com
```

Options:
- `-o`, `--output DIR`: Directory to save the discovery report (default: `output`).
- `-v`, `--verbose`: Enable debug logging.

---

### 2. Probe Live Hosts (Active)
```bash
asm probe output/example.com_20260929T041500Z.json --authorized
```

---

### 3. Scan Common TCP Ports (Active)
```bash
asm portscan output/example.com_20260929T041500Z.json --authorized
```

Options:
- `--authorized`: Confirm authorization to perform active network connections (required).
- `-o`, `--output DIR`: Directory to save the port scan report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Sample Port Scan Output:
```text
[*] Scanning common ports on 2 resolved hosts for 'example.com'...

=== Port Scan Summary ===
Domain:              example.com
Hosts Scanned:       2
Hosts Skipped:       0
Total Open Ports:    8
Skipped Untrusted:   0
Skipped Private IP:  0
Skipped Unresolved:  4
Scan Duration:       6.16s
Report File:         output\example.com_portscan_20260929T045524Z.json

=== Open Ports & Risk Flags ===
[+] example.com
    - 80/http (guess by port)
    - 443/https (guess by port)
    - 8080/http-alt (guess by port)
    - 8443/https-alt (guess by port)
[+] www.example.com
    - 80/http (guess by port)
    - 443/https (guess by port)
    - 8080/http-alt (guess by port)
    - 8443/https-alt (guess by port)
```

### 4. Inspect TLS Certificates and Security Headers (Active)
```bash
asm inspect output/example.com_probe_20260929T041500Z.json --authorized
```

Options:
- `--authorized`: Confirm authorization to perform active inspection against target domain (required).
- `-o`, `--output DIR`: Directory to save the inspection report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Security & Inspection Flags Explained:
- **`expired`**: Certificate validity period ended (`now > not_after`). Browsers will display an invalid certificate warning and block connections.
- **`not_yet_valid`**: Certificate start date is in the future (`now < not_before`).
- **`issuer_equals_subject`**: Certificate subject matches issuer. Indicates a likely self-signed certificate, not definitive proof of untrust.
- **`hostname_mismatch`**: Hostname does not match the Subject Alternative Names (SANs) or Common Name (CN) per RFC 6125.
- **`expiring_soon`**: Certificate expires within 30 days. Needs rotation to prevent service disruption.
- **`deprecated_tls`**: Server negotiated insecure, deprecated TLS protocol versions (`TLSv1.0` or `TLSv1.1`).
- **`hsts_weak`**: `Strict-Transport-Security` is present but `max-age` is under 180 days (15,552,000s), leaving clients vulnerable to downgrade attacks.
- **`server_disclosed` / `x_powered_by_disclosed`**: Response headers leak web server or framework versions (e.g. `Server: cloudflare`, `X-Powered-By: PHP/7.4.3`), assisting attackers in reconnaissance.

Sample Inspection Output:
```text
[*] Inspecting TLS and security headers for live HTTPS hosts of 'example.com'...

=== Inspection Summary ===
Domain:              example.com
Hosts Inspected:     2
Valid Certificates:  2
Expired Certs:       0
Expiring Soon (<=30d): 1
Missing HSTS:        2
Skipped Not HTTPS:   0
Skipped Untrusted:   0
Skipped Private IP:  0
Report File:         output\example.com_inspect_20260929T060910Z.json

=== Host Findings ===
[+] example.com
    - Cert: VALID (expires in 27 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
[+] www.example.com
    - Cert: VALID (expires in 27 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
```

### 5. Risk Scoring & Combined Report (Passive / Local Aggregation)
```bash
asm score --discover output/example.com_20260929T042333Z.json \
          --probe output/example.com_probe_20260929T043830Z.json \
          --portscan output/example.com_portscan_20260929T045524Z.json \
          --inspect output/example.com_inspect_20260929T060910Z.json
```

Options:
- `--discover FILE`: Path to Step 1 discovery report JSON file (**required**).
- `--probe FILE`: Path to Step 2 probe report JSON file (optional).
- `--portscan FILE`: Path to Step 3 portscan report JSON file (optional).
- `--inspect FILE`: Path to Step 4 inspect report JSON file (optional).
- `-o`, `--output DIR`: Directory to save the final score report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Sample Score Output:
```text
Domain Severity Band: HIGH
Total Domain Risk Score: 46 pts
Hosts: 4 total (0 Critical, 2 High, 2 Medium, 0 Low, 0 Info)
  [HIGH] expired.badssl.com  - Expired TLS Certificate (7 pts)
  [HIGH] wrong.host.badssl.com - Untrusted Certificate Authority (7 pts)
  [MEDIUM] self-signed.badssl.com - Self-Signed Certificate (4 pts)
  [MEDIUM] badssl.com - Certificate Expiring Soon (4 pts)
```

> [!NOTE]
> **Heuristic Triage Model (Not CVSS):**
> This scoring model is a heuristic severity model designed for defensive prioritization and attack surface triage. It is **NOT CVSS** and **NOT a guarantee of exploitability**. Scoring evaluates observable internet-facing posture flaws (e.g., exposed databases, expired TLS certificates, missing security headers) to guide remediation, but does not model internal compensating controls, defense-in-depth, or active exploitation.

#### Severity Tiers & Point Values:
- **CRITICAL** (10 pts): Confirmed reachable database services responding with active banners on the public internet.
- **HIGH** (7 pts): Exposed sensitive administrative services (RDP, SMB, Telnet), exposed DB ports without banner, expired/invalid certificates, or untrusted public CAs.
- **MEDIUM** (4 pts): Cleartext protocols (FTP, SMTP, POP3, IMAP), self-signed certificates, certificate hostname mismatches, certificates expiring soon ($\le 30$d), deprecated TLS 1.0/1.1 protocols, or HTTP-only services.
- **LOW** (1 pt): Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), weak HSTS max-age duration, or technology disclosure headers.
- **INFO** (0 pts): Domain attack surface context observations ($\ge 10$ live assets).

#### Host and Domain Band Computation:
1. **Host Severity Band**:
   Derived directly from the host's **worst finding tier**:
   - Any `CRITICAL` finding $\rightarrow$ Host band **CRITICAL**
   - Else any `HIGH` finding $\rightarrow$ Host band **HIGH**
   - Else any `MEDIUM` finding $\rightarrow$ Host band **MEDIUM**
   - Else any `LOW` finding $\rightarrow$ Host band **LOW**
   - Else $\rightarrow$ Host band **INFO** (clean host)
   The numerical point sum serves as a secondary sort key within each band.
2. **Domain Severity Band**:
   Derived from the aggregate host bands:
   - Any `CRITICAL` host $\rightarrow$ Domain band **CRITICAL**
   - Else any `HIGH` host $\rightarrow$ Domain band **HIGH** (flagged as an escalation note if $\ge 3$ high hosts exist)
   - Else any `MEDIUM` host $\rightarrow$ Domain band **MEDIUM**
   - Else any `LOW` host $\rightarrow$ Domain band **LOW**
   
---

## Change Detection Engine (v2.3)

`asm` features an automated attack surface differential engine that compares consecutive successful scans of the same domain to detect newly exposed services, resolved issues, and configuration drift.

### Core Principles & Architecture
1. **Pure Function Engine (`detect_changes`)**:
   Core diffing logic resides in `src/asm/changes.py` as a pure function `detect_changes(baseline_reports, new_reports) -> list[dict]`. It requires no network or database connections and is tested with static JSON fixtures.
2. **Strictly Earlier Baseline Selection**:
   The baseline is selected as the most recent earlier scan for the same domain with `status = 'succeeded'` using `id < :current_id ORDER BY id DESC LIMIT 1`. Failed scans are never used as baselines, and the initial scan of a domain produces zero changes.
3. **Finding-Based Diffing (Single Source of Truth for Severity)**:
   Rather than comparing raw report fields, portscan and inspect changes are derived by diffing findings produced by `src/asm/scoring.py` finding evaluators.
   - **Exposure Additions**: Take the exact severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) of the finding they introduce.
   - **Exposure Reductions**: Are assigned `INFO` severity. A baseline finding is considered resolved only if the host was successfully evaluated in the new scan (`status == "PROBED"`).
   - **Both scans must have inspected the host**: new TLS/header findings become changes only when the host was inspected successfully (`PROBED`) in the baseline *and* the new scan. A host that is new, or was unreachable last time, gets no "removed" or "weakened" changes; its findings still appear in the scan's risk report.
   - **Weak HSTS is `SECURITY_HEADER_WEAKENED`** (since v3.6c): a header that is still present but weak is not "removed". Going from missing to weak HSTS is reported as `SECURITY_HEADER_ADDED`. Changes stored before v3.6c keep their original type (`SECURITY_HEADER_REMOVED`); the API, dashboard and alert emails display both types as stored.
4. **"Unknown" is Not "Absent"**:
   Reconnaissance failures or non-definitive states never generate removal changes:
   - A DNS `TIMEOUT` or `ERROR` does not emit `STOPPED_RESOLVING` (only a definite `RESOLVED` $\rightarrow$ `NXDOMAIN` transition does).
   - An unreachable host or `FILTERED` port does not emit `PORT_NO_LONGER_OPEN` (only `OPEN` $\rightarrow$ `CLOSED` does).
   - A probe timeout does not emit `HTTPS_LOST` (only non-timeout connection/TLS errors do).
   - `HTTPS_LOST` also requires that the baseline scan reached the host over HTTPS; a new host, or one whose HTTPS was already unreachable, is not a loss.
5. **Source Awareness & Truncation Safety**:
   Subdomain removals (`REMOVED_SUBDOMAIN`) are evaluated **only** when both baseline and new scans used the same Certificate Transparency source (e.g. `crt.sh` vs `certspotter`) and neither report was truncated (`truncated: false`). If sources differ or either was truncated, removal detection is safely skipped with a descriptive `skip_reason`.
6. **Atomic & Resilient Finalization**:
   Change detection runs in memory prior to the final worker transaction. If detection encounters an unexpected error, the scan run still marks `succeeded`, recording the error in `scan_runs.change_detection`. Changes and the final status update are inserted atomically in the same database transaction with a unique constraint preventing duplicate change entries: `(scan_run_id, change_type, asset, detail)`.

---

## Scheduled Scans Engine (v2.4a)

`asm` supports opt-in recurring scans per domain, allowing continuous automated monitoring without requiring external task schedulers (such as Celery Beat or cron daemons).

### Key Architectural Invariants
1. **Database-Backed Worker Scheduling**:
   The worker polling loop executes `schedule_due_scans()` at the start of each cycle before claiming queued jobs. It selects due domains (`verification_status = 'verified' AND scan_interval_hours IS NOT NULL AND next_scan_at <= now()`) using `FOR UPDATE SKIP LOCKED`. This allows multiple workers to run concurrently without coordination or duplicated scan jobs.
2. **One Short Transaction Per Domain**:
   Each due domain is locked, evaluated, and updated within its own dedicated short transaction, minimizing lock contention and preventing failures in one domain from affecting others.
3. **Shared Enqueue Function**:
   Both `POST /orgs/{org_id}/domains/{id}/scans` and the worker scheduler call the shared `enqueue_scan()` function to insert the `scan_run` and its 5 `pending` stage tracking rows.
4. **Active Scan Duplicate Suppression**:
   If an active scan (`status IN ('queued', 'running')`) already exists for a domain, the database constraint `uq_scan_runs_active_domain` blocks insertion. The scheduler safely absorbs this constraint violation and advances `next_scan_at` without creating a duplicate job.
5. **No Backfill Guarantee**:
   Following server or worker downtime, `next_scan_at` is always calculated from the current database clock (`now() + interval + jitter`), never from missed historical timestamps. A domain receives exactly **one** catch-up scan rather than multiple stacked scans.
6. **Desynchronization Jitter**:
   A small random jitter (0 to 300 seconds) is added to `next_scan_at` to disperse execution times across the hour and prevent thundering herds on shared network and database infrastructure.
7. **Explicit Trigger Provenance**:
   Every `scan_run` records its origin in the `trigger` column: `"manual"` for user-initiated scans via the API, and `"scheduled"` for automated recurring scans.

---

## Email Alerts & Outbox Engine (v2.4b)

`asm` features an automated email alerting pipeline that dispatches security digests when a scan uncovers new attack surface exposures matching or exceeding a domain's severity threshold.

### Key Architectural Invariants
1. **Transactional Outbox Pattern**:
   Alert notifications are never sent directly within scan execution. Instead, pending notification rows (`alert_notifications` table) are inserted within the **exact same fenced transaction** that records the detected changes and marks the `scan_run` as `succeeded`. This eliminates the dual-write problem: either both the changes and the notification records persist, or neither does.
2. **In-Memory Fault Isolation**:
   Alert digest formatting and recipient resolution run in memory before the final transaction. If formatting raises an unexpected error, the error is sanitized and recorded under `scan_runs.change_detection["alert_error"]`, no alert rows are inserted, and the scan still completes successfully. Alert formatting failures never cause scan failures.
3. **Dedicated Outbox Delivery Polling**:
   At the end of each poll cycle, the worker calls `deliver_pending_alerts()`, claiming due notifications (`status = 'pending' AND next_attempt_at <= now()`) in batches using `SELECT ... FOR UPDATE SKIP LOCKED`.
4. **Row Lock During SMTP Send**:
   The delivery transaction **holds the row lock during the SMTP transmission** (bounded by a strict 10-second socket timeout). This strictly prevents concurrent workers from double-sending the same notification without needing distributed locks or multi-phase commits. Upon success, `status = 'sent'` and `sent_at = now()` are committed, releasing the lock.
5. **Database-Calculated Exponential Backoff**:
   If delivery fails (e.g. SMTP server unreachable or handshake error), the worker records `last_error` and calculates the next retry using native PostgreSQL intervals:
   `next_attempt_at = now() + make_interval(secs => :s)`.
   Retries follow exponential delays (30s, 60s, 120s, 240s) up to 5 attempts before marking `status = 'failed'`.
6. **Injection-Safe Plain-Text Digest**:
   Alert emails are sent as clean, readable plain-text (no HTML) with strict CR/LF sanitization on all headers and subject lines to prevent email header injection attacks. Untrusted report strings are sanitized and truncated.
7. **Local Testing with Mailpit**:
   Delivery is disabled by default when `SMTP_HOST` is empty (`alert_notifications` stay pending). For local development and testing, run Mailpit via the Docker Compose `dev` profile:
   ```bash
   # Start Mailpit (SMTP on 1025, Web UI on http://127.0.0.1:8025)
   docker compose --profile dev up -d mailpit

   # Configure worker environment in .env
   SMTP_HOST=localhost
   SMTP_PORT=1025
   SMTP_FROM=asm-alerts@example.com
   ```
   Open `http://127.0.0.1:8025` in your browser to inspect delivered alert digests in real-time.

---

## Domain Ownership Verification Engine (v3.2)

`asm` replaces the client-asserted `authorized: true` flag with proof of DNS control. An organization may only scan, schedule, or configure alerts for domains it has actively proven ownership of via DNS TXT records.

### Core Architectural Invariants

1. **Proof of DNS Control**:
   Ownership is verified by publishing a high-entropy secret token (`secrets.token_urlsafe(32)`) as a DNS TXT record at a dedicated verification label.
   - **Label Name**: `_asm-verify.<domain>`
   - **Record Type**: `TXT`
   - **Record Value**: `asm-verify=<token>`
   - *Example*:
     For domain `example.com` with token `k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO`:
     ```text
     _asm-verify.example.com.  300  IN  TXT  "asm-verify=k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO"
     ```
   - Multi-string TXT records (RFC 1035 chunking) are joined before evaluation.
   - Per-tenant tokens ensure that verifying a domain in Organization A never grants scanning rights to Organization B.

2. **Verification State Machine**:
   - `pending`: Newly added domain or rotated token; scanning is blocked.
   - `verified`: Successful DNS TXT check or valid operator override; scanning and scheduling allowed.
   - `lapsed`: Domain failed continuous re-verification after 2 consecutive definite misses; monitoring paused.

3. **Check Logic & "Unknown" vs "Absent"**:
   - `MATCH`: Verification succeeds (`status = 'verified'`).
   - `ABSENT`: Definite absence (`NXDOMAIN` or missing/mismatched record). Increments `consecutive_misses`.
   - `UNKNOWN`: Network timeouts, `SERVFAIL`, or DNS server errors. Never counts as a miss; leaves current verification status unchanged.

4. **Continuous Background Re-Verification**:
   - The worker periodically re-verifies `verified` domains approximately once per day (`now() + 24h + jitter`).
   - If a definite miss occurs, a fast retry is scheduled in 1 hour (`now() + 1h`).
   - Only after **2 consecutive definite misses** does status transition to `lapsed`.
   - If a domain lapses, active monitoring and scheduled scans are paused immediately.
   - If domain alerts are enabled, a lapse or operator expiration immediately writes an alert notification to the transactional outbox:
     `"Domain verification lapsed: monitoring paused"`.

5. **Rate-Limited Check Endpoint**:
   - Triggering a manual verification check (`POST /orgs/{org_id}/domains/{domain_id}/verification/check`) enforces a 30-second cooldown under a database row lock (`SELECT ... FOR UPDATE`), preventing abuse across distributed API instances. Returns HTTP 429 if called within cooldown.

6. **End-to-End Enforcement**:
   - `enqueue_scan` (API & worker scheduler) strictly refuses unverified domains with HTTP 422.
   - Worker re-checks domain verification before **every** active pipeline stage (`discover`, `probe`, `portscan`, `inspect`, `score`). If ownership lapses or is revoked mid-scan, the scan immediately terminates and marks `failed`.

7. **Operator Overrides (Time-Bounded Break-Glass)**:
   - Operators can grant manual verification with an audit trail:
     ```bash
     asm admin verify-domain --domain-id 123 --reason "Emergency security audit agreement #441" --expires-in-days 30
     ```
     - `--domain-id DOMAIN_ID`: Target domain ID (required).
     - `--reason REASON`: Non-empty operator justification for override (required).
     - `--expires-in-days EXPIRES_IN_DAYS`: Expiration window in days (default: 30, min: 1, max: 90).
     - Worker automatically moves expired overrides to `pending`.
   - Operators can explicitly revoke an override at any time:
     ```bash
     asm admin revoke-verification --domain-id 123 --reason "Contract completed early"
     ```
     - `--domain-id DOMAIN_ID`: Target domain ID (required).
     - `--reason REASON`: Non-empty operator justification for revocation (required).
   - Operators can suspend and unsuspend accounts (v3.6c):
     ```bash
     asm admin suspend-user --user-id <uuid> --reason "Scanned third-party targets"
     asm admin unsuspend-user --user-id <uuid> --reason "Appeal accepted"
     ```
     - A suspended account gets `403 Account suspended` on its next request; the reason is never shown to users or tenants.
     - Schedules and queued scans stop only in organizations where every owner is suspended. Unsuspending does not turn schedules back on; owners must re-enable them. See `docs/DEPLOY.md`.

### API Endpoints

| Method | Endpoint | Allowed Roles | Description |
|:---|:---|:---|:---|
| `GET` | `/orgs/{org_id}/domains/{domain_id}/verification` | `viewer` | Returns verification status and DNS TXT record instructions |
| `POST` | `/orgs/{org_id}/domains/{domain_id}/verification/check` | `admin` | Checks DNS TXT record now (30s row-locked cooldown, returns 429 on abuse) |
| `POST` | `/orgs/{org_id}/domains/{domain_id}/verification/rotate` | `admin` | Generates a new verification token and resets status to `pending` |

---

## Running Tests and Linting


To run the unit test suite (100% mocked, zero network calls, integration tests deselected):
```bash
pytest
```

To run real network integration tests explicitly (scans `scanme.nmap.org` and `expired.badssl.com`):
```bash
pytest -m integration
```

To run the linter:
```bash
ruff check .
```

---

## Legal and Ethical Use

> [!CAUTION]
> **Authorization & Policy Requirements:** Only scan targets that you own or have explicit written permission to test.
>
> 1. **Active Port Scanning Policy Violations**: Port scanning generates detectable TCP connection sequences. Even against authorized targets or bug bounty scopes, port scanning may violate:
>    - **Network Service Provider (ISP) Acceptable Use Policies (AUP)**: Many residential and commercial ISPs prohibit unsolicited port scanning.
>    - **University, Campus, and Enterprise Network Policies**: Performing port scans from campus or corporate networks without clearance can result in immediate MAC/port disconnection or disciplinary action.
> 2. **Statutory Legal Frameworks**:
>    - **United States**: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)
>    - **United Kingdom**: Computer Misuse Act 1990
>    - **India**: Information Technology Act, 2000 (Section 43: unauthorized access and data downloading; Section 66: computer-related offenses / hacking)
>
> Always respect rate limits, adhere strictly to authorized testing scopes, and never attempt to bypass defensive controls.
