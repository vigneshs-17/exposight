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
  - B-2 committed (`9953a22`): TLS 1.0/1.1 now detected (legacy passes, real handshake tests); untrusted certificates keep expiry, names, issuer and serial (DER parsed with `cryptography`, now a direct dependency); the TLS socket fallback resolves once, refuses any non-public address and connects only to the validated IP with SNI; port-scan DNS runs off the event loop; each probe request's timeouts fit the remaining deadline; 0009/0011 downgrades guarded. Tests: 618 passed (non-browser), 16 browser passed.
  - B-3 committed (`a3ec75a`): `HTTPS_LOST` only when the baseline reached HTTPS; weak HSTS is `SECURITY_HEADER_WEAKENED` (stored older changes keep `SECURITY_HEADER_REMOVED` and still display); missing->weak HSTS is `SECURITY_HEADER_ADDED`; TLS/header changes only for hosts inspected in both scans; `LARGE_ATTACK_SURFACE` in a new report-level `domain_findings` list (shown in the dashboard and counted); header inspection uses the same per-hop deadline budget as the prober and skips the certificate fallback once time is up. Tests: 635 passed (non-browser), 16 browser passed.
  - B-4 committed (`f97ed07`, CI fix `2a98897`): `asm admin suspend-user` / `unsuspend-user`; a suspended account gets 403 "Account suspended" on its next request (fresh DB read per request, separate `get_active_user` dependency) and the dashboard shows a notice; the reason is operator-only; schedules and queued scans stop only in orgs where every owner is suspended (D4); one `account.suspended`/`account.unsuspended` audit event per org (D5); unsuspend does not restart schedules; migration 0013 (guarded downgrade); /terms updated. Tests: 647 passed (non-browser), 17 browser passed.
  - B-5 done, not yet committed: `DELETE /orgs/{id}` (owner) deletes domains (cascading to scans, changes, notifications), memberships and invites and keeps the org row as a `deleted-org-<id>` tombstone with its audit log (`org.deleted` event); 409 while a scan in the org is running, queued scans and schedules cancelled in the same transaction; `DELETE /me` deletes the account, its memberships and invites to its email, one `account.deleted` event per org, 409 naming the orgs while the user is a sole owner (D6), 403 when suspended (deletion requests then go to the operator); the Supabase identity is deleted by the operator on request (D7). Retention purge (D8: scans 180 d keeping each domain's latest successful scan and change baselines, sent/failed notifications 90 d, closed invites 30 d, audit never) in `asm.retention`; worker runs it hourly only with `RETENTION_PURGE_ENABLED=true` (default false, forwarded in compose.prod.yml); `asm admin purge --dry-run | --execute` (D9). /terms, README, DEPLOY.md updated. Tests: 666 passed (non-browser, with DB), 444 passed + 222 skipped without `TEST_DATABASE_URL`, 17 browser passed.

## Plans & Decisions
Plans are written here and approved before coding starts.

### B-5 plan (approved 2026-10-05)
- `DELETE /orgs/{id}` (owner only) turns the org into a tombstone: deletes its domains (cascading to scans, changes, alert notifications), memberships and invites; keeps the org row renamed `deleted-org-<id>` and its audit events (`audit_events.org_id` is `ON DELETE RESTRICT` and the log is append-only); records `org.deleted`. Refused with 409 while any scan in the org is running (same rule as `move-domain`); queued scans and schedules are cancelled in the same transaction as the delete (added 2026-10-06).
- `DELETE /me` deletes the `users` row (memberships cascade) and invites addressed to the user's email; 409 while the user is the only owner of any org (D6). A suspended account cannot self-delete (403); its deletion requests go to the operator.
- Kept for audit, documented: `audit_events` rows (user UUID only), alert recipient addresses other orgs entered and their notifications, the Supabase identity (D7).
- Retention purge (D8): keeps each domain's latest successful scan and any scan still referenced as a change baseline; never touches `audit_events`; runs from the worker behind `RETENTION_PURGE_ENABLED`, plus `asm admin purge --dry-run` (D9).
- /terms updated wherever B-4/B-5 make new things true, with tests.

### Decisions D6-D9 (approved 2026-10-05)
- **D6:** `DELETE /me` while the user is an org's only owner: refuse with 409 naming those orgs; the user transfers ownership or deletes them first. No automatic tombstoning.
- **D7:** Exposight holds no Supabase `service_role` key, so `DELETE /me` cannot remove the Supabase login account. Documented in docs/DEPLOY.md and /terms; the operator deletes the Supabase identity on request.
- **D8:** retention periods: scans 180 days; sent or failed alert notifications 90 days; accepted, revoked or expired invites 30 days; audit events never purged automatically. Keep the latest successful scan and any baseline scan.
- **D9:** purge off by default (`RETENTION_PURGE_ENABLED=false`), admin dry run checked before enabling in production.

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
- Only the table owner role (`exposight_owner`) can disable the audit_events append-only trigger; the app role cannot. Retention purge is off by default (D9); denied requests not logged.
- Rate limits are in-memory and single-process (`--workers 1`); counters reset on api restart.
- Invite tokens are returned to the inviter to share; Exposight does not email them.
- Deletion is API-only (`DELETE /me`, `DELETE /orgs/{id}`); the dashboard has no delete buttons yet.
