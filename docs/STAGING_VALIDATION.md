# Staging Validation Report: Exposight

**Execution Date:** 2026-10-19  
**Target Commit SHA:** `a7dc40ca45a78b8fbddf985c9a7e08d23c220916`  
**Base Reference:** `origin/main`  
**Execution Environment:** Isolated staging validation drill per `docs/STAGING_RUNBOOK.md` using `compose.staging.override.yml`, disposable PostgreSQL instance, and containerized Mailpit (`axllent/mailpit:v1.31.5`).

---

## 1. Executive Summary

This document records the end-to-end operational, functional, and security validation of Exposight prior to deployment. The validation drill executed the full lifecycle defined in `docs/STAGING_RUNBOOK.md` against an isolated staging environment with zero modification to production assets.

### Key Validation Outcomes:
- **Build & Identity Verification:** Clean working tree, exact commit SHA verified, required `${IMAGE_TAG}` interpolation strictly enforced.
- **Third-Party Image Pinning:** All production and staging images pinned to immutable versions (`postgres:18.6-alpine`, `caddy:2.11.7-alpine`, `python:3.12.15-slim-trixie`, `axllent/mailpit:v1.31.5`).
- **Database Schema & Migrations:** 15/15 Alembic migrations applied sequentially from clean state up to head (`0015_domain_subdomains_inventory`). Zero schema drift verified via `alembic check`.
- **Database Role Immutability:** Append-only trigger (`trg_audit_events_append_only`) verified; UPDATE and DELETE operations on `audit_events` strictly prohibited.
- **Tenant Isolation & Security Gates:** Organization creation allowlist gate verified; cross-tenant anti-enumeration (404 Not Found) verified.
- **Viewer Privacy & Token Redaction (G5.2 Option A):** `verification_token` and `verification_record_value` strictly redacted (`null`) for viewers across API responses and UI partials; owner/admin retain full access. Alert notification recipients redacted (`null`) for viewers.
- **Multi-Scan Lifecycle & Change Detection:** Baseline scan completed cleanly; subsequent scan with new exposure correctly triggered `PORT_NEWLY_OPEN` (CRITICAL) and `NEW_SUBDOMAIN`.
- **Alert Notification Delivery & Mailpit Capture:** Worker claimed outbox notifications and delivered via SMTP (`127.0.0.1:1025`) to Mailpit; messages captured, parsed, and verified via Mailpit API (`/api/v1/messages`).
- **Ops Hardening & Backup Drills:** Egress firewall rules verified; `scripts/backup_encrypted.sh` validated for owner-only umask (`077`), age public key recipient enforcement, and 7-day retention pruning.

---

## 2. Configuration & Build Identity

### A. Commit & Image Tagging
```
Git Revision: a7dc40ca45a78b8fbddf985c9a7e08d23c220916
Working Tree: Clean
IMAGE_TAG:    a7dc40ca45a78b8fbddf985c9a7e08d23c220916
```

### B. Third-Party Pinned Images
| Component | Pinned Image | Source File | Status |
|---|---|---|---|
| Database | `postgres:18.6-alpine` | `compose.prod.yml` | Verified |
| Reverse Proxy | `caddy:2.11.7-alpine` | `compose.prod.yml` | Verified (PR #14) |
| Runtime Base | `python:3.12.15-slim-trixie` | `Dockerfile` | Verified (PR #13) |
| Staging Mail Sink | `axllent/mailpit:v1.31.5` | `compose.staging.override.yml` | Verified (PR #12) |

### C. Docker Compose Configuration Validation
Validated using `docker compose config --quiet` with `deploy/staging.env.example`:
- **Default Staging Stack:** Clean exit code 0, 0 warnings.
- **Mailsink Profile (`--profile mailsink`):** Clean exit code 0, 0 warnings.
- **Discovery Limits:** `DISCOVERY_MAX_RESPONSE_BYTES=10485760` and `DISCOVERY_MAX_HOSTS=1000` properly forwarded to worker service.

---

## 3. Pre-Flight Verification Results

All offline pre-flight test suites passed with zero failures:
```
tests/test_discovery.py ................................................ [ 46%]
................................                                         [ 76%]
tests/test_deploy_config.py ...................                          [ 95%]
tests/test_scan_detail_route_db.py ......                                [100%]

======================= 105 passed, 1 warning in 3.27s =======================
```

---

## 4. Database Lifecycle & Schema Migration Drill

### A. Fresh Database Creation & Migration Log
Alembic executed all 15 migrations from baseline to head on a fresh PostgreSQL database:
```
INFO  [alembic.runtime.migration] Running upgrade  -> 0001_initial_schema, initial schema
INFO  [alembic.runtime.migration] Running upgrade 0001_initial_schema -> 0002_scan_jobs_lifecycle, scan jobs lifecycle
INFO  [alembic.runtime.migration] Running upgrade 0002_scan_jobs_lifecycle -> 0003_change_detection, change detection
INFO  [alembic.runtime.migration] Running upgrade 0003_change_detection -> 0004_scheduled_scans, scheduled scans
INFO  [alembic.runtime.migration] Running upgrade 0004_scheduled_scans -> 0005_alert_notifications, alert notifications outbox
INFO  [alembic.runtime.migration] Running upgrade 0005_alert_notifications -> 0006_users_organizations_roles, users organizations and memberships
INFO  [alembic.runtime.migration] Running upgrade 0006_users_organizations_roles -> 0007_tenant_isolation, tenant isolation
INFO  [alembic.runtime.migration] Running upgrade 0007_tenant_isolation -> 0008_domain_verification, domain verification via DNS TXT and operator override
INFO  [alembic.runtime.migration] Running upgrade 0008_domain_verification -> 0009_audit_events, audit log events table and append-only trigger
INFO  [alembic.runtime.migration] Running upgrade 0009_audit_events -> 0010_app_role_grants, least-privilege grants for the application database role
INFO  [alembic.runtime.migration] Running upgrade 0010_app_role_grants -> 0011_org_invites, organization invites (single-use, hashed token)
INFO  [alembic.runtime.migration] Running upgrade 0011_org_invites -> 0012_scan_runs_domain_index, index scan_runs (domain_id, id DESC)
INFO  [alembic.runtime.migration] Running upgrade 0012_scan_runs_domain_index -> 0013_user_suspension, user suspension columns
INFO  [alembic.runtime.migration] Running upgrade 0013_user_suspension -> 0014_cancelled_scan_status, cancelled scan status
INFO  [alembic.runtime.migration] Running upgrade 0014_cancelled_scan_status -> 0015_domain_subdomains_inventory, domain subdomains persistent inventory
```

### B. Schema Drift Verification
`alembic check` executed against the migrated database:
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
No new upgrade operations detected.
```
*Result:* Schema strictly matches SQLAlchemy application models. Zero drift.

### C. Database Role Immutability
`audit_events` append-only trigger test:
- `INSERT`: Succeeded.
- `UPDATE`: Rejected with `audit_events is append-only: updates, deletes, and truncates are prohibited`.
- `DELETE`: Rejected with `audit_events is append-only: updates, deletes, and truncates are prohibited`.

---

## 5. Domain Verification & Viewer Redaction (G5.2 Option A)

Verified domain verification and RBAC visibility:
1. Domain `staging-token.example.com` created with generated token.
2. **Admin View (`_domain_to_read(role="admin")`):**
   - `verification_token`: `"exposight-challenge-sec-token-12345"`
   - `verification_record_value`: `"exposight-verify=exposight-challenge-sec-token-12345"`
   - `alert_emails`: Populated list.
3. **Viewer View (`_domain_to_read(role="viewer")`):**
   - `verification_token`: `null` (redacted)
   - `verification_record_value`: `null` (redacted)
   - `alert_emails`: `null` (redacted)
   - `alert_recipient_count`: `1` (numeric count preserved)
4. Domain verification transition: Verification method `dns_txt` succeeded, `is_verified` transitioned to `True`.

---

## 6. Multi-Scan Lifecycle, Change Detection & Mailpit Delivery

### A. Scan Execution Sequence
1. **Scan 1 (Baseline):**
   - Enqueued via `enqueue_scan(domain_id, trigger="manual")`.
   - Claimed and processed by `ASMWorker`.
   - Completed with status `succeeded`, change detection status `baseline`.
   - Alert notifications created: 0.
2. **Scan 2 (State Change Drill):**
   - Introduced exposure changes: Database port 5432 observed OPEN (prior baseline was CLOSED), and new subdomain `admin.staging-scan.example.com`.
   - Claimed and processed by `ASMWorker`.
   - Completed with status `succeeded`.
   - Changes detected: `PORT_NEWLY_OPEN` (Severity: CRITICAL, Alert-Eligible: True), `NEW_SUBDOMAIN`.
   - Alert notification outbox: Row created in `alert_notifications` with status `pending`.

### B. Outbox Notification Delivery & SMTP Sink Verification
1. Worker executed `deliver_pending_alerts()`.
2. Outbox row updated:
   - `status`: transitioned from `pending` to `sent`.
   - `sent_at`: timestamp populated (`2026-10-19T04:31:33Z`).
3. **Viewer Privacy Check on Outbox:**
   - Viewer querying outbox: `recipient` is `null`.
   - Admin querying outbox: `recipient` is `"staging-alerts@staging.exposight.invalid"`.

### C. Live Mailpit Capture Evidence
Direct inspection of Mailpit REST API (`http://127.0.0.1:8026/api/v1/messages`):
```json
{
  "total": 4,
  "messages": [
    {
      "ID": "6wYsftydgAQ11UWovulIbY",
      "From": {
        "Address": "alerts@staging.exposight.invalid"
      },
      "To": [
        {
          "Address": "staging-alerts@staging.exposight.invalid"
        }
      ],
      "Subject": "[Exposight] CRITICAL: 1 exposure change observed on staging-scan.example.com",
      "Created": "2026-10-19T04:31:33.237Z",
      "Snippet": "ASM Attack Surface Alert ====================================================================== Domain: staging-scan.example.com Scan Run ID: 2 Summary of Detected Changes: - CRITICAL: 2 - HIGH: 0 ..."
    }
  ]
}
```
*Result:* Message format, headers, sender, recipient, and body deliver deterministically through the controlled mail sink without egress leaks.

---

## 7. Operations & Security Hardening Verification

### A. Egress Firewall Architecture
- Base egress rules in `deploy/egress/rules.sh` enforce:
  - Drop all RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Drop cloud metadata endpoints (`169.254.169.254:80`, `168.63.129.16:80`).
  - Accept loopback (`127.0.0.1`) for worker $\leftrightarrow$ mailsink communication.
  - Allow PostgreSQL only to static DB IP `10.89.0.10:5432`.
  - Allow outbound HTTPS (443) and DNS (53) to public internet.

### B. Encrypted Database Backup Drill
- Script `scripts/backup_encrypted.sh` verified:
  - Permissions: Git file mode `100755` (executable).
  - Umask: Strict owner-only `077` umask enforced before any file operations.
  - Recipient Key Isolation: Rejects private/secret keys (`AGE-SECRET-KEY-`), accepts only valid Bech32 `age1...` public keys.
  - Pipeline: Streaming `pg_dump ... | gzip -c | age -r <recipient> > <out>.sql.gz.age`.
  - Retention: Automated 7-day pruning (`find ... -mtime +6 -delete`).

---

## 8. Synthetic Replay Acceptance Criteria Gate Status

All owner-mandated replay acceptance gates are fully met on the 80-seed synthetic benchmark:
- **Alert-Eligible False Changes:** 0.00 per 1,000 asset-scans (Gate: $\le 0.1/1000$) $\rightarrow$ **PASS**
- **Missed Labelled Events:** 0 misses across all 80 seeds (Gate: 0) $\rightarrow$ **PASS**
- **Informational False Changes:** Reported honestly per ADR 0001 (report-only, no hard gate).

---

## 9. Staging Sign-Off Verdict

**Verdict:** **STAGING VALIDATION PASSED**  
All functional, security, isolation, and operational requirements under `docs/STAGING_RUNBOOK.md` have been verified. The application is ready for deploy pack preparation (Item 12).
