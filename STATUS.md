# Status

## Test Suite
- Test counts: see the CI run on the latest commit

## Done
- v1 CLI: 5-stage reconnaissance scanner core (`discover`, `probe`, `portscan`, `inspect`, `score`).
- v2.0.0 Service: FastAPI REST API, PostgreSQL persistence, PostgreSQL-backed background job queue (FOR UPDATE SKIP LOCKED), CT Cert Spotter fallback.
- v2.3 Change Detection: Finding-based differential engine with severity-aware transitions.
- v2.4 Scheduling & Alerts: Periodic scheduler (`FOR UPDATE SKIP LOCKED`) and transactional outbox email alerts.
- v3.1a User Auth & Organizations: Supabase JWT auth, JIT user provisioning, organizations RBAC (`owner`, `admin`, `viewer`).
- v3.1b Tenant Isolation: Foreign keys, strict organization-scoped queries, anti-enumeration (404 on cross-tenant), legacy quarantine migration.
- v3.2 Domain Verification: Proof of DNS control via DNS TXT (`_asm-verify.<domain>`), continuous re-verification, scan gating, break-glass operator overrides with expiry.
- v3.3 Audit Log: Append-only audit_events table, trigger against app tampering, 15 structured actions, and organization audit API.
- v3.4a Dashboard Shell & Verification UI: Server-rendered dashboard (FastAPI + Jinja2 + HTMX), Supabase browser authentication, organization switcher, domains inventory, and DNS TXT verification UI.
- v3.4b Scans, Results & Changes UI: Scans list (latest 20 runs, status, trigger, duration, changes summary), Run scan button (gated by domain verification and role), scan detail with 5 pipeline stages, Fix first prioritized findings (capped at 50 with overflow count), per-tier count cards, and changes table with auto-polling (3s, 15m cap).
- v3.4c Schedule, Alerts & Audit Log UI: Domain schedule settings (presets Off/6h/12h/24h/7d/30d), alerts settings with email chips and viewer redaction, domain alert history outbox log with offset paging, and organization audit log with action/domain filtering, keyset pagination, and escaped metadata.
- v3.4d Playwright Browser Tests: End-to-end browser tests in Chromium against live uvicorn server; RBAC, polling, 401 retry, 0 CSP violations.
- v3.5 Landing Page: GET / public page, GSAP 3.15.0 vendored (Standard no-charge license, not MIT), CSS 3D, reduced-motion + no-JS safe, strict CSP unchanged. Tests: 443 passed (non-browser), 15 browser passed.

## In Progress
- v3.6b security hardening, checkpoint A-1 done (not yet committed): production startup guard (`ENVIRONMENT=production`), API docs off in production, nosniff/no-store on JSON API, https-only Supabase origin in CSP; no token-header echo in `WWW-Authenticate`, JWKS stale-key serving, failure backoff and `PyJWKSetError` -> 503; SMTP credentials refused without TLS, `SMTP_SSL` option; alert-recipient changes in audit metadata (counts only), duplicate-domain race -> 409, `move-domain` resets verification/alerts/schedule and refuses during active scans. Tests: 523 passed (non-browser), 15 browser passed.
- Checkpoint A-2 next: least-privilege Postgres role, org invites, rate limits/quotas, Terms page.

## Next
- v3.6: deploy (scope to be planned).

## Skills Plan
- **Installed**: Docker (x4: `docker-build-strategies`, `docker-compose-patterns`, `docker-destructive-guardrails`, `docker-project-foundations`), `arena`, `frontend-design`, `webapp-testing`, `security-and-hardening`, GSAP (x6: `gsap-core`, `gsap-performance`, `gsap-plugins`, `gsap-scrolltrigger`, `gsap-timeline`, `gsap-utils`).
- **Later (each only when its phase starts)**:
  - `greensock/gsap-skills`: v3.5 landing page.
  - `coreyhaines31/marketingskills` or `claude-seo`: only if launching publicly.
  - `remotion-dev/skills`: demo video.

## Known Limitations
- DNS lookup during manual check runs while holding the domain database row lock (bounded about 5s).
- Integration test suite requires PostgreSQL (SQLite is unsupported for DB tests).
- The table owner can disable the audit_events append-only trigger; no retention/purge; denied requests not logged.
