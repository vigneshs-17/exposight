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
- v3.6b security hardening done: A-1 (`afc9b70`) and A-2 (`3c43fca`) committed.
- v3.6c Phase B, checkpoint B-1 committed (`11b156d`): log redaction of emails, secret URL parameters and JWTs in api/worker/admin logs (uvicorn access log included); worker delivery-failure logs no longer name the recipient; a security-gate failure mid-scan no longer overwrites stages that already succeeded; index `scan_runs (domain_id, id DESC)` (migration 0012); downgrades of 0007/0008 refuse to lose data unless `ALLOW_DATA_LOSS_DOWNGRADE=1`; alert subject `[Exposight]` and remaining user-visible "ASM" text. Tests: 601 passed (non-browser), 16 browser passed.
- Phase B remaining, in order:
  - B-2 done, not yet committed: TLS 1.0/1.1 now detected (legacy passes, real handshake tests); untrusted certificates keep expiry, names, issuer and serial (DER parsed with `cryptography`, now a direct dependency); the TLS socket fallback resolves once, refuses any non-public address and connects only to the validated IP with SNI; port-scan DNS runs off the event loop; each probe request's timeouts fit the remaining deadline; 0009/0011 downgrades guarded. Tests: 618 passed (non-browser), 16 browser passed.
  - Found, not fixed (outside B-2 scope): `headers_inspect.inspect_single_host` still uses fixed per-request httpx timeouts, so its 10 s deadline is only checked between hops.
  - B-3: change detection and scoring (`HTTPS_LOST` only after a real HTTPS loss, `SECURITY_HEADER_WEAKENED`, diff only hosts inspected in both scans, `domain_findings` for `LARGE_ATTACK_SURFACE`).
  - B-4: account suspension mechanism (block API + UI, cancel schedules in orgs where every owner is suspended, admin CLI suspend/unsuspend, per-org audit events, tests). Not implemented yet: no way to suspend an account exists today.
  - B-5: account and org deletion endpoints + retention/purge job (off by default, dry run first). Not implemented yet: data is kept until deleted; deletion is manual.

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
- Only the table owner role (`exposight_owner`) can disable the audit_events append-only trigger; the app role cannot. No retention/purge; denied requests not logged.
- Rate limits are in-memory and single-process (`--workers 1`); counters reset on api restart.
- Invite tokens are returned to the inviter to share; Exposight does not email them.
