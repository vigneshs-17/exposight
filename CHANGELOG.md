# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Operations & Automation
- **Automated Production Deployment**: Added single-command deployment harness (`scripts/deploy.ps1` and `scripts/deploy_remote.sh`) for Azure production releases, featuring automated prechecks, remote database backup with local scp copy, fast-forward pull, compose rebuild with migrate exit code validation, egress firewall verification, and live HTTP security assertion.

#### User Authentication & Organizations (v3.1a)
- **Supabase JWT Authentication**: Dependency-injected token verification (`verify_access_token`, `JWKSManager`) validating RS256/ES256 signatures against Supabase JWKS endpoints with cache TTL, min refresh interval, and fail-closed security.
- **Just-In-Time (JIT) User Provisioning**: Automatic upsertion of authenticated users into the `users` table upon verified token presentation.
- **Organization & Role-Based Access Control**: Multi-tenant organizations with membership roles (`owner`, `admin`, `viewer`) and role hierarchies (`ROLE_RANKS`).
- **Organization Management Endpoints**: Endpoints for organization creation (`POST /orgs`), listing (`GET /orgs`), and member management (`POST /orgs/{id}/members`, `PATCH /orgs/{id}/members/{user_id}`, `DELETE /orgs/{id}/members/{user_id}`).
- **Last-Owner Invariant**: Enforced constraint preventing demotion or removal of an organization's final owner.

#### Tenant Isolation (v3.1b)
- **Multi-Tenant Scoping**: All domains and scans partitioned by organization ID (`org_id`); API routes scoped under `/orgs/{org_id}/...`.
- **Anti-Enumeration Security Invariant**: Non-members attempting to access an organization's resources receive HTTP 404 (Not Found), never HTTP 403 (Forbidden), preventing organization ID enumeration.
- **Database-Level Isolation**: `domains.org_id` foreign key with per-organization uniqueness `(org_id, name)`; scans, results and alerts are scoped through their domain. Every tenant query filters by `id` and `org_id` in SQL.
- **Legacy Quarantine Migration (0007)**: Creates a quarantine organization identified by `system_kind = 'legacy_quarantine'` (never by name) and assigns existing domains to it.
- **Operator Move-Domain CLI**: Administrative command `asm admin move-domain --domain-id <id> --target-org-id <id>` for moving quarantined domains to target organizations.

#### Domain Ownership Verification via DNS TXT (v3.2)
- **Proof of DNS Control**: Replaced client-asserted `authorized: true` with proof of DNS control using high-entropy secret tokens (`secrets.token_urlsafe(32)`) published as DNS TXT records at `_asm-verify.<domain>`.
- **DNS TXT Check Engine**: Resolver logic with `dnspython` joining multi-string RFC 1035 TXT chunks and matching `asm-verify=<token>`.
- **Failure Taxonomy**: Tri-state check logic: `MATCH` (verified), `ABSENT` (definite negative: NXDOMAIN or missing/mismatched record), `UNKNOWN` (indeterminate: timeout, SERVFAIL, network error; never counts as a miss).
- **Verification State Machine**: State tracking (`pending`, `verified`, `lapsed`) with centralized transition function `apply_check_outcome()`.
- **Continuous Re-Verification**: Daily worker re-checks with randomized jitter; 2-miss threshold with 1-hour fast retries before transitioning to `lapsed`.
- **Scan Gating**: Endpoints and worker refuse scans for unverified domains (`HTTP 422 Unprocessable Content`). Worker verifies domain ownership before every active stage (`discover`, `probe`, `portscan`, `inspect`, `score`), halting mid-scan if lapsed or revoked.
- **Rate-Limited Verification API**: `GET /verification` for instructions, `POST /verification/check` with a 30-second database row-locked cooldown, and `POST /verification/rotate` to reset token and status.
- **Outbox Lapse Alerts**: Atomic emission of transactional outbox email notifications (`"Domain verification lapsed: monitoring paused"`) upon domain lapse or operator override expiration.
- **Operator Break-Glass Overrides**: Administrative CLI `asm admin verify-domain --domain-id <id> --reason "<text>" [--expires-in-days <1..90>]` and `asm admin revoke-verification --domain-id <id> --reason "<text>"` with mandatory justifications and bounded expiration.

#### Audit Log & Event Tracking (v3.3)
- **Append-Only Audit Events Table (0009)**: Migration `0009_audit_events` creates `audit_events` table with BigInteger primary key, foreign key `org_id` referencing `organizations(id)` (`ON DELETE RESTRICT`), actor type check constraint (`user`, `operator`, `system`), nullable `actor_user_id` UUID without foreign key, `action`, `target_type`, `target_id`, `metadata` JSONB, and `created_at` timestamptz. Covered by composite indexes `(org_id, id)` and `(org_id, target_type, target_id)`.
- **Append-Only Database Trigger**: PostgreSQL trigger `trg_audit_events_append_only` and function `prevent_audit_events_tampering()` raising exceptions on any `UPDATE`, `DELETE`, or `TRUNCATE` operations against `audit_events` (attached via migration and SQLAlchemy model `after_create` DDL).
- **15 Structured Lifecycle Actions**: Complete instrumentation across user, operator, and system actions:
  - Organizations: `org.created`
  - Memberships: `membership.added`, `membership.role_changed`, `membership.removed`
  - Domains: `domain.created`, `domain.schedule_changed`, `domain.alerts_changed`
  - Verification: `verification.checked`, `verification.rotated`, `verification.operator_granted`, `verification.operator_revoked`, `verification.lapsed`, `verification.override_expired`
  - Movement & Scans: `domain.moved` (dual-event recorded in source and target orgs in the same transaction), `scan.queued` (manual scan runs only; idempotent replays emit no duplicate events).
- **Metadata Sanitization & Redaction**: Strict per-action allowlisted keys and expected types; unknown or wrong-typed keys raise `ValueError`. Never stores tokens, JWTs, emails, or IP addresses. Free-text values (`org.created` name, operator reasons) are truncated to 500 characters, and email/IP patterns are masked as `[redacted]`. Serialized event metadata is hard-capped at 2048 bytes.
- **Organization Audit API**: `GET /orgs/{org_id}/audit-events` restricted to `admin` and `owner` roles (viewer 403, non-member 404) with `domain_id` and `action` filters and keyset cursor pagination (`limit` capped at 100, `before_id` cursor, ordered by `id DESC`).
- **Transactional Atomicity**: Single helper `record_event(session, ...)` adds events to the caller's session without committing or flushing, guaranteeing that failed or rolled-back operations never leave orphan audit records.

#### Dashboard Shell & Domain Verification UI (v3.4a)
- **FastAPI + Jinja2 + HTMX Architecture**: Lightweight server-rendered dashboard without node or npm build dependencies, adding runtime dependency `jinja2>=3.1.4` and bundling templates and static assets in Python package data.
- **Client Application Shell (`GET /app`)**: Public application shell container delivering Supabase project URL and publishable key via HTML body `data-*` attributes with zero inline scripts or styles.
- **Supabase Browser Authentication**: Direct client-side sign-in with `@supabase/supabase-js` UMD bundle storing session in `sessionStorage` (memory module variable updated via `onAuthStateChange`). User passwords go directly to Supabase and never touch application server memory.
- **Synchronous HTMX Token Propagation**: Synchronous `htmx:configRequest` event listener injecting `Authorization: Bearer <token>` into all outbound HTMX fragment requests, with automatic single-retry token refresh on HTTP 401.
- **Read-Only HTML Fragment Routes**:
  - `GET /ui/empty-org`: Onboarding view for users without an organization.
  - `GET /ui/orgs/{org_id}/domains`: Organization domain inventory with sentence-case status badges and role-gated domain addition form.
  - `GET /ui/orgs/{org_id}/domains/{domain_id}`: DNS TXT proof-of-control verification details with record copy buttons, immediate verification check, and token rotation.
- **Zero Duplicate Write Logic**: All write operations in the browser dispatch asynchronous `fetch()` requests directly to existing JSON API endpoints (`POST /orgs`, `POST /orgs/{org_id}/domains`, `POST .../verification/check`, `POST .../verification/rotate`) and refresh views with `htmx.ajax()`.
- **Strict Content Security Policy & Headers**: HTTP security headers middleware on `/app`, `/ui/*`, and `/static/*` enforcing `default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `font-src 'self'`, `img-src 'self' data:`, `connect-src 'self' <SUPABASE_URL>`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on all `/ui/*` endpoints.
- **HTMX Inline Style Injection Prevention**: Configured `<meta name="htmx-config" content='{"includeIndicatorStyles": false, "allowEval": false, "allowScriptTags": false}'>` in `<head>` preventing HTMX from injecting inline indicator `<style>` tags blocked by CSP.
- **XSS & DOM Hardening**: Jinja autoescaping enabled on all templates, `htmx.config.allowEval = false`, `htmx.config.allowScriptTags = false`, zero occurrences of `innerHTML` in client code, and dynamic check outcome and error rendering using `textContent` only.
- **Vendored Static Assets**: Pinned releases for `htmx` (2.0.11), `@supabase/supabase-js` (2.117.2), and self-hosted IBM Plex Sans and Mono font files with SIL Open Font License 1.1, verified and tracked in `src/asm/static/vendor/VENDOR.md`.

#### Scans, Results & Changes UI (v3.4b)
- **Scans Inventory Route (`GET /ui/orgs/{org_id}/domains/{domain_id}/scans`)**: Read-only fragment listing the latest 20 scans for a domain with status badges, trigger, started-at timestamp, execution duration, and structured change summary (`format_change_summary` summing worker tier counts). Omits loading heavy `ScanResult` reports on list rows.
- **Role-Gated Run Scan Action**: Client "Run scan" button rendered only for `admin` and `owner` roles. Rendered disabled with visible hint (`"Domain ownership verification required to run scans."`) when domain verification status is not `verified`. Dispatches `POST /orgs/{org_id}/domains/{domain_id}/scans` with an `Idempotency-Key` header and navigates to the scan detail on success.
- **Scan Detail Route (`GET /ui/orgs/{org_id}/scans/{scan_id}`)**: Read-only fragment showing scan metadata, 5 pipeline stages (`discover`, `probe`, `portscan`, `inspect`, `score`) with execution status and durations, Fix first prioritized findings, and detected changes.
- **Fix First Finding Prioritization (`extract_fix_first_findings`)**: Pure presentation function sorting findings by severity tier (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`), score points descending, target host ascending, and port ascending (`None` port precedes numeric ports). Findings table capped at 50 rows with an overflow count (`"... and N more findings."`).
- **Summary Count Cards**: Displays Domain score, Risk band, and counts for Critical, High, Medium, and Low tiers computed across all parsed findings before the 50-row cap, keeping counts consistent with findings data.
- **Scan Changes Section**: Displays delta changes from `ScanChange` database records with severity, category, change type, asset, detail, and evidence (or `"No changes detected in this scan."`).
- **Conditional Polling & 15-Minute Cap (`check_polling_status`)**: Scan detail container emits HTMX polling attributes (`hx-get`, `hx-target="this"`, `hx-swap="outerHTML"`, `hx-trigger="every 3s"`) only while scan status is `queued` or `running` and created within the last 15 minutes. Omitted entirely for finished scans to prevent re-fetching on user click. Active scans older than 15 minutes stop polling and render a warning banner (`"Still <status> after 15 minutes. Automatic updates have stopped."`) with a manual `"Refresh"` button.
- **401 Token Refresh Swap Preservation**: HTMX `responseError` listener preserves the source element's `hx-swap` attribute (`outerHTML`) during token refresh retry, avoiding nesting duplicate polling containers.
- **Stored-XSS Defenses & Template Guard Test**: All attacker-influenced finding and change fields (evidence, why-it-matters, titles, assets, details, stage errors) are rendered strictly as autoescaped text in `<code>` blocks and standard elements, never as active links (`<a href>`). Verified by `test_templates_have_no_csp_blocked_inline_code` preventing inline styles, inline scripts, and event handlers across all Jinja2 templates.
- **WCAG AA Accessible Palette Tokens**: Updated Tungsten warning text to `--color-tungsten-text: #a84b00` (5.43:1 contrast on `#fff8f0`, exceeding WCAG AA 4.5:1), and established Signal Crimson tokens (`--color-signal-crimson: #a81a2e`, 7.36:1 on `#ffffff` and 6.77:1 on `#fdf3f4`).

#### Schedule, Alerts & Audit Log UI (v3.4c)
- **Schedule Configuration Section**: Added schedule management panel to `domain_detail.html` displaying current cadence (`Not scheduled` or `Every N hours`) and next scan timestamp. Admin/owner form provides standard presets (`Off`, `Every 6 hours`, `Every 12 hours`, `Every 24 hours`, `Every 7 days`, `Every 30 days`) and dynamically preserves non-preset intervals (`Every N hours (current)`). Unverified domains keep `Off` enabled while disabling active presets with a visible hint (`"Domain ownership verification required before scheduling automated scans."`). Dispatches `PUT /orgs/{org_id}/domains/{domain_id}/schedule` via `app.js`.
- **Email Alerts Configuration Section**: Added alert settings panel with enable/disable toggle, minimum severity selector (`Critical`, `High`, `Medium`, `Low`, `Info`), and dynamic email chip input supporting up to 5 recipient addresses. On unverified domains, alerts cannot be enabled, but disabling alerts and clearing recipients is permitted (Decision A). Viewers see only recipient count (`"N recipients configured"`), never recipient emails. Dispatches `PUT /orgs/{org_id}/domains/{domain_id}/alerts` via `app.js`.
- **Domain Alert History Route (`GET /ui/orgs/{org_id}/domains/{domain_id}/alert-notifications`)**: Read-only fragment displaying outbox notifications for a domain with offset pagination (50 per page, `Previous` / `Next`), delivery status badges (`Sent`, `Pending`, `Failed`), attempts count, and collapsible message body (`<details class="alert-body-details">`).
- **Viewer Privacy & SMTP Exception Protection**: `Recipient` and `Last error` table columns in `alert_notifications.html` are strictly restricted to `admin` and `owner` roles, preventing raw SMTP exception text (which often embeds target recipient addresses) from leaking recipient emails to viewers.
- **Organization Audit Log Route (`GET /ui/orgs/{org_id}/audit-events`)**: Read-only audit trail restricted to `admin` and `owner` roles, featuring action dropdown filtering (15 lifecycle actions), domain dropdown filtering, and keyset cursor pagination (`"Older events"` via `data-before-id`, `"Newest"` reset). Event metadata is serialized to a standard string via Python `json.dumps` and rendered as escaped JSON in `<pre><code>` blocks.
- **Shared Audit Query Builder (`build_audit_query`)**: Centralized audit query constructor in `src/asm/audit.py` shared by both the JSON API (`routes.py`) and UI fragment (`routes_ui.py`), supporting keyset pagination (`before_id`), filters, and optional outer join with `users` for actor email display.
- **Template Security Guard Enhancement**: Updated `test_templates_have_no_csp_blocked_inline_code` to ban `tojson` and `|safe` filters across all Jinja2 templates, guaranteeing all JSON and attacker-influenced data is autoescaped.

#### Playwright Browser Tests (v3.4d)
- **End-to-End Browser Test Suite**: Added 10 Playwright Chromium tests under `tests/browser/` verifying browser workflows against an in-process live Uvicorn server thread on an ephemeral port.
- **Zero In-Tree Auth Backdoors**: Implemented synthetic JWT-shaped token generation and token registries strictly within `tests/browser/helpers.py` and `tests/browser/conftest.py`. The production application code (`src/`) has zero test hooks and rejects synthetic tokens with HTTP 401.
- **Browser State Machine & UI Verification**: Automated verification for sign-in, zero runtime CSP violations, viewer RBAC privacy with complete email omission, schedule/alerts validation on unverified domains (Decision A), 5-email chip limits, scan detail auto-polling and cleanup, 401 token refresh retry preserving a single container, audit log keyset navigation, and DNS verification result DOM persistence.
- **Strict Network & Runtime Guards**: Automatic fixture teardown assertions enforcing zero CSP violation events, zero unhandled page errors, zero unexpected 5xx or non-favicon 404 responses, and zero outbound network egress. Added an autouse patch forbidding real DNS lookups in browser tests.

### Changed
- **Pytest Default Options**: `pyproject.toml` `addopts` now deselects the `browser` marker by default (`-m 'not integration and not browser'`), keeping default test execution fast and offline.
- **Dedicated Browser Test CI Job**: Added `browser-test` workflow job in `.github/workflows/ci.yml` running Playwright tests against PostgreSQL and recording trace/screenshot artifacts on failure.
- **Alerts Update on Unverified Domains**: `PUT /orgs/{org_id}/domains/{domain_id}/alerts` now accepts `alerts_enabled=false` on unverified domains, so alerts can be switched off and recipients removed after a lapse; enabling still returns 422.
- **BREAKING (API)**: Removed `authorized` and `authorization_note` fields from `DomainCreate` request schema and database models. Client can no longer assert authorization.
- **BREAKING (Database)**: Migration `0008_domain_verification` resets all existing domains to `verification_status = 'pending'`, pausing automated scheduled scans until DNS verification is completed.
- **Alert Trigger Rules**: `should_trigger_alerts` requires explicit `verified: bool` argument; removed deprecated `authorized` parameter.

### Fixed

#### Discovery & Certificate Transparency Fallback
- **Empty CT Log Handling**: When `crt.sh` returns zero in-scope names, discovery treats the response as inconclusive and falls back to Cert Spotter with `fallback_reason="crt.sh returned no in-scope names"`. If Cert Spotter fails or returns zero names, `discovery_empty=True` is recorded in the discovery report, and the scan detail page renders an explicit warning banner (`"No hosts discovered — results incomplete"`) instead of falsely claiming `"No findings"`.
- **Change Detection Guard**: Verified and enforced that empty-discovery scans (`discovery_empty=True` or 0 discovered hosts) evaluate to `UNKNOWN` observations, never qualify as absences, and reset consecutive absence streaks to 0, preventing false `REMOVED_SUBDOMAIN` emissions.
- **Operational Note**: The first successful scan after this fix for targets affected by earlier empty-discovery scans may emit one `NEW_SUBDOMAIN` change event for hosts missed by those earlier scans — this is expected behavior as valid asset inventory is restored.

## [2.0.0] - 2026-10-01

### Added

#### API & Database Persistence (v2.1)
- **FastAPI REST Service**: Endpoints for target domain management (`POST /domains`, `GET /domains`), scan initiation (`POST /domains/{id}/scans`), status/progress tracking (`GET /scans/{id}`), and artifact retrieval (`GET /scans/{id}/results/{stage}`).
- **PostgreSQL Storage & Migrations**: SQLAlchemy ORM models (`Domain`, `ScanRun`, `ScanStage`, `ScanResult`, `ScanChange`, `AlertNotification`) with automated Alembic migrations and drift checks.
- **Safety & Authorization Gates**: Preserved non-negotiable security controls requiring explicit target authorization (`authorized: true`) and strict domain normalization before scanning.

#### Asynchronous Scan Worker & Job Queue (v2.2)
- **Database-Backed Job Queue**: Asynchronous worker claiming jobs via PostgreSQL `FOR UPDATE SKIP LOCKED` without external message broker dependencies.
- **Fenced Execution**: Fencing token (`claim_token` UUID) validation per stage to prevent zombie worker overwrites.
- **Crash Recovery & Heartbeats**: Lease-based worker recovery with exponential backoff and randomized SQL jitter.
- **Terminal State Invariants**: Atomic guarantee that failing a scan transitions any remaining stages cleanly to `failed` or `skipped`.
- **Containerized Architecture**: Multi-stage, non-root Docker Compose setup for API, worker, and database services.

#### Certificate Transparency Fallback (v2.2.1)
- **SSLMate Cert Spotter Integration**: Automated fallback from `crt.sh` to the Cert Spotter API upon primary aggregator failures or timeouts.
- **Bounded Pagination & Rate Limiting**: Pagination capped at 10 pages / 5,000 entries with HTTP 429 `Retry-After` backoff handling.
- **Structured Discovery Metadata**: Reports record discovery `source` (`crt.sh` vs `certspotter`), sanitized `fallback_reason`, and `truncated` status.
- **Unified Error Hierarchy**: `DiscoveryError` base class with `CrtshError`, `CertSpotterError`, and `AllSourcesFailedError`.

#### Attack Surface Change Detection (v2.3)
- **Finding-Based Differential Engine**: Pure function (`detect_changes`) comparing reports between consecutive succeeded scans against `scoring.py` finding evaluators.
- **Definitive Severity Mapping**: Additions inherit finding severities (`CRITICAL` to `LOW`); reductions are classified as `INFO` only when verified on active hosts.
- **"Unknown is Not Absent" Invariant**: DNS timeouts, unreachable hosts, and filtered ports are treated as indeterminate and never produce false removal changes.
- **Source & Truncation Guards**: Subdomain removals are evaluated only when baseline and new scans share discovery sources and neither was truncated.
- **Changes Query API**: Endpoints for querying historical changes (`GET /domains/{id}/changes` and `GET /scans/{id}/changes`) with filtering and pagination.

#### Scheduled Scans Engine (v2.4a)
- **Database-Backed Polling**: Background worker claims due scheduled scans (`schedule_due_scans`) each cycle via `FOR UPDATE SKIP LOCKED`.
- **Per-Domain Cadence**: Configurable scan intervals (6 to 720 hours) with randomized jitter to disperse network and database load.
- **Shared Enqueue Pipeline**: Unified `enqueue_scan()` used by both manual API triggers and the automated scheduler with trigger provenance.
- **No-Backfill Guarantee**: System downtime results in a single catch-up scan with schedule advanced from current time.
- **Active Scan Suppression**: PostgreSQL partial unique index prevents concurrent active scans for the same domain.
- **Schedule Management API**: `PUT /domains/{id}/schedule` endpoint to configure, update, or disable automated scanning.

#### Transactional Outbox Email Alerts (v2.4b)
- **Transactional Outbox Pattern**: Atomic insertion of `alert_notifications` within the same transaction that commits detected changes and marks a scan succeeded, eliminating dual-write risks.
- **In-Memory Fault Isolation**: Alert formatting runs prior to transaction; formatting errors are captured in `change_detection["alert_error"]` without failing the scan run.
- **Worker Outbox Delivery**: Dedicated polling (`deliver_pending_alerts`) using `FOR UPDATE SKIP LOCKED`, holding the row lock during SMTP transmission with a 10s socket timeout to prevent concurrent duplicate sends; delivery is at-least-once.
- **CRLF Injection Defense & Sanitization**: Headers sanitized of `\r` and `\n`; email addresses validated via Pydantic `EmailStr`; plain-text digests with finding truncation.
- **Exponential Backoff**: Failed delivery attempts retried via SQL `next_attempt_at = now() + make_interval(secs => :s)` up to 5 attempts.
- **Alert Settings & History API**: `PUT /domains/{id}/alerts` for threshold configuration and `GET /domains/{id}/alert-notifications` for delivery audit logs.
- **Local Mailpit Environment**: Added Mailpit mock SMTP service under Docker Compose `dev` profile for local testing.

---

## [1.0.0] - 2026-09-29

### Added

#### 5-Stage Reconnaissance Scanner Core (CLI)
- **Phase 1: Passive Subdomain Discovery (`asm discover`)**:
  - Certificate Transparency queries against `crt.sh` with backoff and retry.
  - Multi-threaded DNS resolution using `dnspython` for `A` and `AAAA` records.
  - Wildcard stripping, domain normalization, and scope enforcement.
- **Phase 2: Active Host Probing (`asm probe`)**:
  - Mandatory `--authorized` confirmation gate.
  - SSRF protections blocking private, loopback, link-local, and reserved IP ranges.
  - HTTPS first, then HTTP, on ports 80/443 web availability probing with in-scope redirect following (max 5) and 64 KB response streaming cap.
- **Phase 3: TCP Port Scanning (`asm portscan`)**:
  - Asynchronous TCP connect scan over 16 common service ports (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`).
  - Polite pacing and concurrency limits (max 10 ports per host, max 5 hosts concurrently).
  - Passive and polite banner grabbing with 256-character truncation.
- **Phase 4: TLS & Header Inspection (`asm inspect`)**:
  - TLS certificate validation (expiration, hostname mismatch, self-signed/untrusted, deprecated protocols).
  - Security header evaluation across six monitored headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) and information-disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Phase 5: Heuristic Risk Scoring (`asm score`)**:
  - Severity-tier triage (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`); host band = worst finding, points only as a tiebreaker; explicitly not CVSS; every finding carries host, port, source and evidence.
- **CLI Interface**: Single unified command-line entry point with JSON report export.
