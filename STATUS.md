# Status

## Test Suite
- Test counts: see the CI run on the latest commit

## Current Status Checklist

### Implemented and locally verified
- **Scanner observation validity & history traversal (E-1a)**:
  - Port observations: `OPEN` and `CLOSED` are definite; `FILTERED`, `TIMEOUT`, and missing observations are treated as unknown. Traverses up to 3 earlier scans for latest definite state with accurate per-change `baseline_scan_run_id` attribution.
  - HTTPS inspection observations: Decoupled certificate and header validity. Per-field header evidence tracking (HSTS strength transitions: added, weakened, removed requiring prior presence/strength).
  - Certificate defect completeness & remediation: Affirmative proof requirement (`_is_defect_remediated`) before resolving defect findings; identity-only certificates cannot resolve defects; issuer-before-not_after rotation ordering preserved.
  - CT discovery consistency: Bounded 3-scan history window; scan-level non-truncation/source gate vs. per-host non-empty qualification; anchor-source comparability; 2 consecutive qualifying absences before `REMOVED_SUBDOMAIN`; single emission on entry into absence; rediscovery as `NEW_SUBDOMAIN` referencing confirmed absent scan; transient noise recovery; immediate `NEW_SUBDOMAIN` on first observed asset; clean separation between discovery membership and DNS resolution transitions (`NEWLY_RESOLVING`, `STOPPED_RESOLVING`).
  - Worker first-scan baseline contract: First successful scan for a domain establishes a baseline (`status="baseline"`, `changes=[]`, `removal_detection="skipped"`); bypasses alert generation completely with zero change-based notifications and zero `scan_changes` rows.
  - Bounded HTTPS-loss confirmation: Requires 2 consecutive qualifying failures (`CONNECT_ERROR` or `TLS_ERROR` while HTTP answers, matching `HTTP_NO_HTTPS` prerequisite) and prior successful reachability within the 3-prior-scan window; single emission on entry; unknown/inconclusive observations reset failure streak.
- **Database integration & schema migrations**:
  - Full migration cycle verified against PostgreSQL 18.6: `alembic upgrade head` (14 migrations) -> `alembic check` (0 drift) -> `alembic downgrade -1` -> `alembic upgrade head` (all exit 0).
  - Multi-baseline queries and domain isolation verified with real PostgreSQL queries (`tests/test_change_detection_db.py`, `tests/test_alerts_db.py`, `tests/test_b3_change_type_compat_db.py`, `tests/test_b5_deletion_retention_db.py`).
  - Full non-browser test suite with PostgreSQL and coverage gate: 940 passed, 27 deselected (25 browser tests + 2 live network integration tests), 0 failed; line+branch coverage 90.57% (exceeds pyproject 90.0% gate).
- **Browser regression suite (Playwright)**:
  - 26 browser tests passed across Chromium against isolated PostgreSQL container with synthetic auth, CSP violation capture, and route abortion guards.
  - Includes focused regression `test_browser_scan_detail_changes_and_baseline_rendering` testing baseline scan (0 changes), subsequent scan changes (`REMOVED_SUBDOMAIN`, `NEW_SUBDOMAIN`, `HTTPS_LOST`, `CERTIFICATE_CHANGED`, `SECURITY_HEADER_WEAKENED`, `PORT_NEWLY_OPEN`), and viewer role restrictions.
- **Current working tree regression & hygiene checks**:
  - DNS pinning regression suite in `tests/test_d1_dns_pinning.py` passes as part of the test suite.
  - Security headers (H-Hdr-1) verified via `tests/test_hdr1_security_headers.py`.
  - UI themes C-UI-1 through C-UI-4 verified via `tests/test_cui4_error_pages.py`, `tests/test_cui4_theme.py`, and `tests/test_dashboard_css.py`.
  - Code hygiene: `ruff check .` clean (0 errors), `git diff --check` clean (0 warnings).
- **Historical checkpoint verification (prior commits)**:
  - Phase D-1 (`4346252`): DNS pinning negative controls with local HTTPS test server.
  - Phase D-2 (`2c53a3e`): Worker egress firewall container rules verified via `scripts/egress_check.py` on Azure VM and in local compose.

### Implemented but awaiting verification
- **Remote CI pipeline execution**:
  - GitHub Actions CI workflows (`.github/workflows/ci.yml` and `.github/workflows/security.yml`) have not yet executed against this local working tree. Local execution of tests and linters does not establish or substitute for remote CI pass.

### User-reported deployed behavior
- **Production deploy of `170cbd0` on 19 Oct 2026 (https://exposight.dev)**, owner-run with `docs/DEPLOY_NEXT.md`:
  - Pre-deploy: VM at `ec52e8e`, schema `0014_cancelled_scan_status`, clean tree; backup `exposight_db_20261019_075856Z.sql.gz` (gzip OK, 12 tables) copied to the owner laptop.
  - `migrate` exited 0 (`0014_cancelled_scan_status -> 0015_domain_subdomains_inventory`); db, egress and api healthy; worker and caddy (2.11.7) running.
  - Worker `egress check: PASSED`.
  - Checked from outside the VM: `/health` 200 with database connected; CSP with `frame-ancestors 'none'`, HSTS, nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, no `Server` header; `security.txt` and `/privacy` served. A `HEAD /` request answers 405 (open item for the next test pass).
  - Scheduled scan #23 of `exposight.dev` succeeded in all 5 stages (15 s) while crt.sh returned 502: discovery fell back to Cert Spotter. The first scan after `0015` reported no changes, so the inventory bootstrap did not flag known subdomains as new.
  - DNS hardening live: apex `v=spf1 -all`, `_dmarc` `p=reject`, CAA for `letsencrypt.org` and `sectigo.com` (Caddy's ZeroSSL fallback), no wildcard issuance.
- **Azure VM deployment (`2e886e2`)**:
  - User reports Exposight is live on Azure VM (`exposight.indiasouthcentral.cloudapp.azure.com`).
  - Caddy automatic TLS certificate provisioning via Let's Encrypt.
  - Worker egress firewall check (`scripts/egress_check.py`) reported passing in VM container environment (IMDS and WireServer blocked).
  - Database backup and restore drill (`scripts/backup_db.sh`) reported passing into temporary test database.
  - *Note*: Deployment status is recorded as user-reported; the current local working tree (including H-Hdr-1, C-UI-4, and E-1a consistency changes) has not been deployed to Azure, and live configuration has not been independently verified in this session.

### Planned product work & unconfirmed deployment status
- **C-UI-5 dashboard layout redesign**:
  - Redesign plan specifying new Overview layout, org-level scans/alerts views, and scan detail presentation is parked in `STATUS.md` awaiting approval before implementation.
- **Unconfirmed production deployment items (need live confirmation)**:
  - Custom domain wiring (`exposight.dev`): noted as pending in earlier deployment logs; current live DNS/TLS status requires confirmation.
  - External SMTP transport and alert dispatch: earlier notes record live SMTP delivery as pending; current live configuration requires confirmation.
  - Off-VM automated backup replication: backup creation and local restore drills verified; replication off-host noted as pending in earlier logs and requires confirmation.

### Unresolved release criteria
- **Replay benchmark stop-rule criteria (seeds 1-20, 7,080 asset-scans)**:
  - Combined false changes per 1,000 asset-scans: **89.83** (target threshold: $\le 1.0$) — **FAILS** (driven primarily by CDN certificate rotation at 41.24/1k and synthetic port flap at 19.92/1k).
  - Alert-eligible false changes per 1,000 asset-scans: **0.85** (target threshold: $\le 0.1$) — **FAILS** (driven by 6 synthetic `PORT_NEWLY_OPEN` events from `port_flap_closed`; port policy retained as deliberate unresolved tradeoff).
  - Missed real events: **1** (target threshold: $\le 0$) — **FAILS** (Seed 12 `cert_rotated` under `cdn_edge`).

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
  - B-5 committed (`ae5cd34`): `DELETE /orgs/{id}` (owner) deletes domains (cascading to scans, changes, notifications), memberships and invites and keeps the org row as a `deleted-org-<id>` tombstone with its audit log (`org.deleted` event); 409 while a scan in the org is running, queued scans and schedules cancelled in the same transaction; `DELETE /me` deletes the account, its memberships and invites to its email, one `account.deleted` event per org, 409 naming the orgs while the user is a sole owner (D6), 403 when suspended (deletion requests then go to the operator); the Supabase identity is deleted by the operator on request (D7). Retention purge (D8: scans 180 d keeping each domain's latest successful scan and change baselines, sent/failed notifications 90 d, closed invites 30 d, audit never) in `asm.retention`; worker runs it hourly only with `RETENTION_PURGE_ENABLED=true` (default false, forwarded in compose.prod.yml); `asm admin purge --dry-run | --execute` (D9). /terms, README, DEPLOY.md updated. Tests: 666 passed (non-browser, with DB), 444 passed + 222 skipped without `TEST_DATABASE_URL`, 17 browser passed.
  - B-6 committed (`ba26c4f`): scans cancelled by suspension or org deletion are stored as `cancelled` with a neutral reason ("Scanning is paused for this organization." / "The organization was deleted."); the dashboard shows a grey "Cancelled" badge and a "Scan cancelled" note; retention treats `cancelled` as finished; migration 0014 rewrites the two old "Cancelled: ..." rows shapes and its downgrade restores them. Docker tag and remaining "ASM SaaS" text now Exposight (distribution name `asm-saas` kept). Our 7 uses of `HTTP_422_UNPROCESSABLE_ENTITY` replaced with `422`; pytest fails on any Starlette "'HTTP_...' is deprecated" warning; `alembic.ini` sets `path_separator = os`. `scripts/reset_test_db.py` rebuilds the local test DB with Alembic; the `db_engine` fixture no longer runs `create_all` and fails unless the DB is at Alembic head; the CI browser job runs `alembic upgrade head`. Tests: 673 passed (non-browser, with DB), 445 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; same counts under Python 3.12.12.
- v3.6c Phase D (plan in Plans & Decisions):
  - D-1 committed (`4346252`), reviewed and verified (2026-10-07): DNS pinning. Prober (both schemes, every redirect hop, unverified retry), header inspection (steps A and D), the TLS certificate fallback and all port connects use the IP that passed the SSRF check, resolved once per host per stage; hostname kept for `Host`, SNI and certificate verification (`scan_common.pin_host` / `pinned_request`, httpcore `sni_hostname`). First IPv4 else IPv6 (D11); IPv6 off unless `SCAN_IPV6_ENABLED=true` (D12), IPv6-only hosts reported as `SKIPPED_IPV6_ONLY`; `httpcore>=1.0,<2` (D16). Tests: 694 passed (non-browser, with DB), 466 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; 12 revert proofs caught.
  - D-2 committed (`2c53a3e`): worker egress firewall. `egress` service (`deploy/egress/`, Alpine 3.22.2 + iptables, only container with `NET_ADMIN`) owns the namespace; the worker uses `network_mode: "service:egress"`. Postgres allowed only to the db's static `10.89.0.10:5432`; private/loopback/link-local/CGNAT/reserved IPv4 rejected ("No route to host"); IPv6 dropped; DNS 1.1.1.1 / 9.9.9.9; `app-tier` `ip_range: 10.89.0.128/25`. `scripts/egress_check.py` passes locally; without the firewall it fails (`api:8000 CONNECTED`); a halfway-failing rules script leaves the worker in `Created`. CI job `egress-firewall` (D15, not yet run on GitHub). DEPLOY.md "Worker egress firewall" with the Phase H checklist. Tests: 705 passed (non-browser, with DB), 477 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; 4 live and 10 static revert proofs caught.
- v3.6c Phase G (plan in Plans & Decisions) committed (`605ca91`): security gates in CI. New `security.yml` (push/PR/weekly): bandit on `src/` (0 findings; 9 accepted with `# nosec B###` and a reason: 2 B501, 2 B608, 5 B311; 3 B110 fixed with specific exceptions + debug logs), pip-audit `--strict` on the frozen installed set (0), gitleaks full history (8 false positives listed by fingerprint with reasons in `.gitleaksignore`; 0 after), trivy on the app and egress images (fixable HIGH/CRITICAL: 7 -> 0 via runtime `apt-get upgrade`, 21 -> 0 via `alpine:3.22.6`; `pip` removed from the runtime image). `db-test` runs the full non-browser suite with coverage `fail_under = 90`, `precision = 2` (measured 90.63% line+branch). Dependabot watches `/deploy/egress`. README badges, SECURITY.md policy. Tests: 706 passed (with DB, coverage gate), 478 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; every gate shown failing on a deliberate change and passing after revert.
- v3.6c Phase E cleanup committed (`354433f`): distribution renamed `exposight` (brand test now rejects `asm-saas`/`asm_saas` anywhere in tracked files); the two `roles.py` `# nosec B608` are still needed (removing them: bandit `-ll` B608 x2, exit 1), restored with one-line reasons; the only warning from our code (a browser test left an `HTTPError` response open, ResourceWarning in the next test) fixed; Caddy access logs stay off (Option A, Caddyfile unchanged); every `compose.prod.yml` service has json-file log rotation 10m x 3 (one YAML anchor, tested). Tests: 707 passed with DB (coverage 90.65%), 479 passed + 228 skipped without DB, 17 browser passed. One no-DB run showed 1 failed / 3 warnings that was not captured and did not reproduce in 14 full and 15 targeted reruns (open: possible flaky test).
- Phase H-Azure-1 committed (`3a6ab93`): the Azure WireServer `168.63.129.16` is blocked in the worker egress firewall (`deploy/egress/rules.sh`) and refused by `is_safe_public_ip` (also in IPv4-mapped, NAT64 and 6to4 forms); `scripts/egress_check.py` requires it BLOCKED; DEPLOY.md has an Azure subsection.
- R-1 (E-3, E-6) committed (`37c236a`): `tests/test_route_isolation_db.py` classifies all 49 entries in `app.routes` (40 application routes: 18 TENANT_SCOPED, 14 LIST_SCOPED, 8 PUBLIC_OR_SELF; plus 8 FastAPI docs/openapi GET/HEAD routes and the `/static` mount); a meta-test fails on any unclassified or stale route. Org B's owner gets 404 on every tenant-id route with org A's ids (51 cases, `/ui` included), no org-A data in any body, org A's rows unchanged after every write attempt; 16 list cases contain no org-A ids, including `?domain_id=<org A>` on audit events; `POST /invites/accept` with org A's token is the one documented 403. No leak or cross-tenant write found. README title/status and STATUS updated. Tests: 796 passed with DB, 485 passed + 311 skipped without `TEST_DATABASE_URL`, 17 browser passed; 3 revert proofs caught.
- E-1a (review "Task 2") committed (`992a3f1`): offline replay harness `experiments/change_replay/` (plan in Plans & Decisions), `tests/test_change_replay.py`, `EXPERIMENTS.md`. No `src/`/`migrations/` change. Result over seeds 1-20 (7,080 asset-scans per profile): zero noise gives 0 false changes and detects all 180 labelled events at delay 0; the combined realistic profile gives 157.63 false changes per 1,000 asset-scans, 11.86 alert-eligible per 1,000 and 7 missed events, so all three stop-rule bounds fail and P0 is not negligible under this noise model (P1 needs approval; real noise rates should be measured first). Output byte-identical across runs and `PYTHONHASHSEED` values. Tests: 500 passed + 311 skipped without `TEST_DATABASE_URL`; with DB 806 passed, 5 failed (the alembic-subprocess migration tests in `test_b1_worker_migrations_db.py` and `test_b6_cancelled_scans_db.py` hit their 120s timeout because every new psycopg connection on this machine currently waits until its `connect_timeout` and hangs without one; environmental, not caused by this change); 17 browser passed.
- E-4 (review item E-4) committed (`0f4ca49`, plan in Plans & Decisions): verification record is now `_exposight-challenge.<domain>` = `exposight-verify=<token>`; the legacy `_asm-verify` record is still accepted. The check (api "Check now" and worker re-verification) asks the resolvers in `VERIFICATION_RESOLVERS` (default 1.1.1.1, 9.9.9.9; `configure=False`, never the host resolver; passed through to `api` and `worker` in `compose.prod.yml` with the same default when unset, checked by `tests/test_deploy_config.py`) with DO/AD; an AD match from one resolver, or a match from all resolvers, verifies; disagreement is UNKNOWN. No migration. Token lifetime (never expires) documented in DEPLOY.md; expiry and legacy-label removal in IDEAS.md. No doc named the egress Alpine version as current, so none changed. Tests: 822 passed, 19 deselected with `TEST_DATABASE_URL`; 17 browser passed; 510 passed + 311 skipped + 19 deselected without `TEST_DATABASE_URL` (before the compose test was added); `ruff check .` and `bandit -r src -ll` clean; 3 revert proofs caught.
- H-Auth-1 committed (`df6be35`, plan in Plans & Decisions): `POST /orgs` returns 403 unless the caller's email is in `ORG_CREATION_ALLOWED_EMAILS` (JSON list, default `[]` = nobody; trimmed, lower-cased, validated as emails at startup; passed to `api` in `compose.prod.yml`). Invites are unchanged, so non-listed users still join by invite. `/ui/empty-org` shows the create form only to listed users, otherwise an invite-only notice. DEPLOY.md: sign-up OFF for the demo, invitee onboarding (operator creates the Supabase user with auto-confirm, then the org admin sends the invite token), the new setting; `.env.production.example` updated; IDEAS.md: alert-recipient limits. Tests: 830 passed, 19 deselected with `TEST_DATABASE_URL`; 17 browser passed; `ruff check .` and `bandit -r src -ll` clean; revert proof (check removed) failed the 403 tests.
- H-Fix-1 committed (`2e886e2`, plan in Plans & Decisions): `docker-compose.yml` passes `ORG_CREATION_ALLOWED_EMAILS` (api) and `VERIFICATION_RESOLVERS` (api, worker) with the app defaults, tested for both compose files; dashboard accept-invite form (`partials/accept_invite.html`, on the no-org screen and under each domain list) calls `POST /invites/accept`, switches to the joined org or shows the API reason; DEPLOY.md onboarding uses the form, suspension cancels queued scans as `cancelled`. Tests: 834 passed, 21 deselected with `TEST_DATABASE_URL`; 19 browser passed; `ruff check .` and `bandit -r src -ll` clean; revert proof (handler disabled) failed both new browser tests.
- Live deploy 2026-10-13: Azure VM `exposight.indiasouthcentral.cloudapp.azure.com`, commit `2e886e2`. Let's Encrypt certificate issued by Caddy. `scripts/egress_check.py` PASSED in the worker (IMDS `169.254.169.254` and WireServer `168.63.129.16` BLOCKED); host control: IMDS reachable, WireServer `000` as a normal user and `200` as root (the Azure agent's host rule allows only root). PASSED again after `docker compose restart egress` and a full reboot. `scripts/backup_db.sh` ran (8.0K dump, mode 600). UFW allows 22/80/443 only; sshd password authentication off. Restore drill PASSED: the latest backup (`exposight_db_20261013_011833Z.sql.gz`) restored with `psql --single-transaction` into a temporary database `exposight_restore_test` in 0.299 s, exit 0; the pre-check found no `\connect`, role or database statements in the dump; live and restored were identical (users 1, organizations 1, memberships 1, domains 0, audit_events 1, alembic head `0014_cancelled_scan_status`, audit trigger 1, 12 tables owned by `exposight_owner`); live `/health` stayed ok during the drill; the temporary database was dropped. Not done yet: custom domain (`exposight.dev`), SMTP, an off-VM backup copy.
- H-Deploy-1 committed (`abdaafc`, plan in Plans & Decisions): `scripts/backup_db.sh` tracked as `100755` (cron on the VM failed with "Permission denied"); `tests/test_deploy_config.py` checks the git mode of every `scripts/*.sh`. DEPLOY.md: `sudo mkdir` + `chown` of `/opt/exposight` before cloning, Supabase JWT Keys must be ECC/RSA (not legacy HS256), cron line uses `bash /opt/exposight/scripts/backup_db.sh`.
- C-UI-1 committed (`0597903`, plan in Plans & Decisions): dark landing page rebuilt with CSS only. Space Grotesk variable woff2 (22.3 KB, OFL, `static/fonts/SpaceGrotesk-OFL.txt`) plus the existing IBM Plex Mono; hero pipeline card in CSS 3D with stages lighting up in sequence under a scanning beam, receding grid and radar sweep; scroll-driven depth reveals and parallax inside `@supports (animation-timeline: view())`; "How it works" (Add domain, Verify, Scan, Alert) pinned with `position: sticky` and a named view timeline at 900 px and wider; feature cards tilt with the pointer (`landing.js`, 1.4 KB, `style.setProperty` only); Lucide icons inline (ISC). `prefers-reduced-motion: reduce` removes all motion and tilt. The landing page no longer loads GSAP, ScrollTrigger, `app.css` or IBM Plex Sans: about 95 KB of assets instead of about 322 KB (the vendored GSAP files stay; nothing else loads them now). CSP header, dashboard, API and auth unchanged. Tests: GSAP-specific browser tests rewritten for the CSS version, plus a pinned-sequence test; new unit tests for local-only resources, the self-hosted font and licence, and the reduced-motion block. 838 passed, 22 deselected with `TEST_DATABASE_URL`; 20 browser passed; `ruff check .` and `bandit -r src -ll` clean; revert proofs: a Google Fonts link, a missing reduced-motion block, motion leaking into reduced motion and an unpinned section each failed their test.
- gitleaks CI fix committed (`db7ef9e`): the high-entropy fake publishable key in the C-UI-1 `_landing_html()` test fixture replaced with a short low-entropy placeholder; the reviewed finding in history commit `0597903` added to `.gitleaksignore` by fingerprint.
- C-UI-2 committed (`ef9f429`, plan in Plans & Decisions): landing page restyled to `DESIGN.md` (near-black neutrals, cyan accent, severity colours, 4/8 px radii). Fonts: Plus Jakarta Sans variable (27.3 KB) and Inter variable (48.3 KB), latin subset, OFL licence files; IBM Plex Mono kept (49.2 KB); Space Grotesk removed. Landing font payload 124.8 KB. New: status pill, decorative domain box linking to `/app`, trust labels, "Example" panel with a CSS conic-gradient radar and example scan feed, "From apex domain to exposed subdomains" with example topology and inventory table (example.com names, 192.0.2.0/24 and 198.51.100.0/24 addresses, findings as `scoring.py` would report them), ownership-verification section, roles card, floating glass pill nav (active section via IntersectionObserver class toggle, hidden below 480 px). Pinned "How it works" cut from 400vh to 200vh and card fades shortened (hold 10-90 %), so a step card is always in focus and a full-page render shows under one viewport of empty space. Copy checked against the code; "live" dropped from the discovery text. Tests: font tests for the three fonts and their licences; new unit test for "Example" labels, reserved names and documentation IPs, and the DESIGN.md do-not-use terms; new browser tests for the pinned section (height <= 2 viewports, a card in focus at 21 scroll steps) and the pill nav. 839 passed, 24 deselected with `TEST_DATABASE_URL`; 22 browser passed; `ruff check .` and `bandit -r src -ll` clean. Revert proofs: 400vh pin, the old 20/80 crossfade, an `acme-corp.com` row, a missing "Example" label and a removed pill-nav class toggle each failed their test. Screenshots in `output/c-ui-2-screenshots/{before,after}/`.
- C-UI-3 committed (`d2d2037`, plan in Plans & Decisions): signed-in dashboard restyled to the `DESIGN.md` tokens, CSS and header markup only. `app.css` rewritten: near-black canvas, `--surface-2` panels with `--border`, `--surface-1` header/inputs/table header, mono uppercase table headers, cyan only on primary buttons, focus ring, running scans and the logo. Pill chips in IBM Plex Mono: verified/succeeded green, pending/lapsed/queued amber, failed red, running cyan, skipped/cancelled neutral; severity Critical/High/Medium/Low/Info. Chip text for Critical and Low uses one step lighter than DESIGN.md (`#F87171`, `#60A5FA`) because `#EF4444`/`#3B82F6` measure 4.0:1 on the hover row, below AA; every text/chip pair measured at 5.1:1 or more. Header: radar logo mark (inline SVG, same as landing), org switcher, email, Sign out; wraps at 390 px. Inline forms stack and table cells stop wrapping under 640 px, so tables scroll inside their container; the old design scrolled the whole page sideways at 390 px. Hover/focus transitions only, all off under `prefers-reduced-motion: reduce`. Fonts: Inter + Plus Jakarta Sans + IBM Plex Mono (already self-hosted); the two IBM Plex Sans woff2 files are now unused and removed. No change to `app.js`, routes, auth, HTMX attributes, IDs or class names; CSP unchanged. Tests: new `tests/test_dashboard_css.py` (local fonts only, tokens, every status/tier chip, reduced motion, header controls); `test_dashboard_ui.py` font/concept assertions updated. 844 passed, 27 deselected with `TEST_DATABASE_URL`; 23 browser passed; `ruff check .` and `bandit -r src -ll` clean. Revert proof: a removed chip class and a removed reduced-motion rule each failed. Screenshots (domain list, domain detail, scans list, audit log; 1440 px and 390 px) in `output/c-ui-3-screenshots/{before,after}/`.
- H-Hdr-1, done, not yet committed (plan in Plans & Decisions): the two Low findings from the live scan. `add_security_headers_middleware` sets `X-Frame-Options: DENY` on every response that passes through it (correction, found during C-UI-4 planning: responses from the unhandled-exception handler (500) run in Starlette's outermost `ServerErrorMiddleware`, outside this middleware, and carried no security headers at all until C-UI-4), and API/404/docs responses without a CSP get `Content-Security-Policy: frame-ancestors 'none'` (page CSP unchanged; it already had `frame-ancestors 'none'`). uvicorn runs with `--no-server-header` in `compose.prod.yml` and `docker-compose.yml` (the Dockerfile entrypoint is `asm`, so no change there); the Caddyfile drops `Server` with `header -Server`. Tests: new `tests/test_hdr1_security_headers.py` (both headers on `/`, `/app`, `/terms`, a 404; each compose `api` command parsed by uvicorn's CLI gives `server_header=False` and a live uvicorn started with it sends no `Server` header; Caddyfile has `header -Server`); `test_caddyfile_content_invariants` now allows exactly HSTS and `-Server`. 852 passed, 26 deselected with `TEST_DATABASE_URL`; 24 browser passed; `ruff check .` and `bandit -r src -ll` clean. Revert proofs: removing the `X-Frame-Options` line, the framing-only CSP, `--no-server-header` or `header -Server` each failed its test.
- C-UI-4, done, not yet committed (plan in Plans & Decisions): theme finished. Error pages: `templates/error.html` (radar logo, "Error NNN", title, one sentence, links to `/` and `/app`, `noindex`, never echoes the path or the error) for 404/403 and 500 when the request accepts `text/html` and is not under `/orgs`, `/invites`, `/me`, `/health`, `/ui`, `/static`, `/docs`, `/redoc`, `/openapi.json`; everything else keeps its JSON. Security headers now come from one function, `apply_response_security_headers`, called by the middleware and by the 500 handler (which runs outside every middleware: before C-UI-4 a 500 had no security headers). Every response now also gets `Referrer-Policy: no-referrer` (API responses had none) and every error response `Cache-Control: no-store`. `/terms` loads only `landing.css`, uses the radar logo (old "EXP" badge gone) and has `.terms-content`/`.terms-updated` styles. `static/favicon.svg` linked from landing, terms, dashboard and error pages. `static/og-image.png` (1200x630, 72 KB) with absolute `https://exposight.dev/static/og-image.png`, `summary_large_image` on `/` and `/terms`. `landing.js` shows "Open dashboard" when a `sessionStorage` key matches `^sb-.+-auth-token$` (key names only, try/catch, no fetch). `/app` has a meta description and `robots noindex`. DESIGN.md section 9 documents `--border-hover: #3F3F46` (now a token in `app.css`) and the AA chip text colours. Test fixture keys in `test_dashboard_ui.py` are `anon_key_1`. Tests: new `tests/test_cui4_error_pages.py` (14, full header set on HTML and JSON 404/403/500), `tests/test_cui4_theme.py` (11), one new `test_dashboard_css.py` test, one browser test (four label cases). 878 passed, 27 deselected with `TEST_DATABASE_URL`; 25 browser passed; `ruff check .` and `bandit -r src -ll` clean; gitleaks history scan: no leaks. 11 revert proofs failed as expected. Screenshots in `output/c-ui-4-screenshots/`.

## Plans & Decisions
Plans are written here and approved before coding starts.

### IC-1 plan: fixes from the independent check (requested 2026-10-19, report `D:\exposight-reports\independent-check-2026-10-19.md`)
Branch `fix/independent-check-1` from `origin/main` `389901f`, one PR, test-first for every behaviour change, no migration.
- F1 (D-IC1): `uv.lock` is the source of truth. `requirements/runtime.lock.txt` and `requirements/dev.lock.txt` are exported from it with hashes (`uv export --frozen --no-emit-project`). The Docker image installs `runtime.lock.txt` with `pip install --require-hashes --no-deps`, then the project wheel with `--no-deps`. CI test jobs install `dev.lock.txt` the same way, then `pip install --no-deps -e .`. The pip-audit job audits `dev.lock.txt` (a superset of runtime) and fails if `uv.lock` or the exports are out of date with `pyproject.toml`.
- F2: `/` and `/health` answer GET and HEAD; HEAD has the same status and headers and no body. The HEAD routes are separate decorators with `include_in_schema=False` (one route with both methods gave duplicate OpenAPI operation ids), and both are in the isolation registry as public.
- F3 (D-IC2): the per-IP limit covers every request without a verified identity. `get_active_user` marks the request as verified; `get_current_user` marks a rejected token as already charged. After the handler runs, the middleware charges the IP for any request that carried an `Authorization` header but was neither verified nor charged, and answers 429 when the limit is used up. Only side-effect-free public routes reach that point, so replacing their response is safe.
- F4: `/health` caches the database check result for 2 s (injectable clock, lock).
- F5: `Permissions-Policy: camera=(), microphone=(), geolocation=()` on every response, from `apply_response_security_headers`.
- F7: the redactor also masks `scheme://user:password@`, `password: value`, JSON `"access_token": "..."` (and refresh/id tokens, password, secret), and bare `token=value`.
- F8: a cached JWKS key is served during an outage only while the last successful fetch is under 24 h old; after that the request fails closed (503).
- F9: the worker claim log uses `lease=<first 8 chars>` instead of `token=<uuid>`.
- F10: Caddyfile drops `Via` (`header -Via`) and serves the HTTP-to-HTTPS 308 from an explicit `http://` site that drops `Server`.
- F11: dated DEPLOY_NEXT checklist item for Supabase "Confirm email" ON and "Allow new users to sign up" OFF.
- F13: `GET /robots.txt` (`Allow: /`, `Disallow: /app`), public in the registry.
- F6 (digest/SHA pinning) and F12 (HSTS includeSubDomains/preload): deferred, recorded in `docs/DECISIONS_PENDING.md`.
- Result (2026-10-19, local, deps installed from `requirements/dev.lock.txt` with `--require-hashes`, Python 3.12.12): 1260 passed, 40 deselected, 91.37% line+branch; 38 browser passed; `ruff check .` and bandit clean; pip-audit on the lock: no known vulnerabilities. 20 revert proofs failed with their expected messages. Docker image built from `runtime.lock.txt` (fastapi 0.146.0, starlette 1.9.0, pip removed). Caddyfile checked with real `caddy:2.11.7-alpine`: HTTP 308 has no `Server`, HTTPS has no `Via`/`Server`, HSTS kept. No migration.

### Final build batch plan (requested 2026-10-19, Claude Code sole builder)
Worktree `D:\exposight-final-wt` from `origin/main` `2534056`. One PR per item; related doc items may share one.
1. Fix `docs/DEPLOY_NEXT.md`: target = current main SHA, VM `Standard_B2als_v2` (x86_64), pre-deploy `backup_db.sh` + PowerShell `scp` to `D:\exposight-backups\`, `git pull --ff-only` + `up -d --build` (migrate is a service), alembic_version via `$POSTGRES_USER`/`$POSTGRES_DB`, egress check / headers / `/health` / worker / one manual scan, rollback restores into a dropped and recreated database, 0015 populated downgrade blocked by design.
2. Docker log rotation (json-file 10m x 3) on every service: already on main with `test_every_service_has_log_rotation`; no change.
3. `/.well-known/security.txt` (RFC 9116), `text/plain`, Expires under one year ahead, test.
4. `/privacy` page on the landing theme, matching the code; linked from landing, terms and app footers; tests.
5-8. Owner docs: `docs/EMAIL_SETUP.md` (Brevo, `notify.exposight.dev`, 587 STARTTLS), `docs/DNS_RECORDS.md`, `docs/BACKUP_SETUP.md` (age, cron 03:30 UTC, weekly scp, restore test), `docs/MONITORING_SETUP.md`.
9. Cert Spotter key: `CERTSPOTTER_API_KEY` Bearer support already on main with test; add the terms question to `docs/DECISIONS_PENDING.md`.
10. Repo hygiene: report only, delete nothing.

### B-5 plan (approved 2026-10-05)
- `DELETE /orgs/{id}` (owner only) turns the org into a tombstone: deletes its domains (cascading to scans, changes, alert notifications), memberships and invites; keeps the org row renamed `deleted-org-<id>` and its audit events (`audit_events.org_id` is `ON DELETE RESTRICT` and the log is append-only); records `org.deleted`. Refused with 409 while any scan in the org is running (same rule as `move-domain`); queued scans and schedules are cancelled in the same transaction as the delete (added 2026-10-06).
- `DELETE /me` deletes the `users` row (memberships cascade) and invites addressed to the user's email; 409 while the user is the only owner of any org (D6). A suspended account cannot self-delete (403); its deletion requests go to the operator.
- Kept for audit, documented: `audit_events` rows (user UUID only), alert recipient addresses other orgs entered and their notifications, the Supabase identity (D7).
- Retention purge (D8): keeps each domain's latest successful scan and any scan still referenced as a change baseline; never touches `audit_events`; runs from the worker behind `RETENTION_PURGE_ENABLED`, plus `asm admin purge --dry-run` (D9).
- /terms updated wherever B-4/B-5 make new things true, with tests.

### B-6 plan "leftovers" (requested 2026-10-06)
1. **Cancelled scans (D10):** new scan status `cancelled` (free-text column, no constraint to change). Suspension (`_stop_org_scanning`) and `DELETE /orgs/{id}` write `status='cancelled'` with a short neutral reason in `error`: "Scanning is paused for this organization." / "The organization was deleted." Dashboard: "Cancelled" badge in neutral colours (label from the existing `capitalize()` fallback) and a neutral "Scan cancelled" note instead of the red "Scan failed" box. API: `status` is returned as stored; `?status=cancelled` filter works. Retention purge treats `cancelled` as finished. Migration 0014 (data only) rewrites the two exact old rows shapes (`failed` + the old "Cancelled: ..." text) to the new status and text; downgrade restores them exactly. `asm admin move-domain` cancels nothing (it refuses while a scan is queued or running), so it needs no change. Alerts: a cancelled scan never runs change detection, so no alert can be queued; alert history shows notification delivery status, not scan status, so nothing changes there.
2. **Branding:** Docker image tag `asm-saas` -> `exposight` in CI and README. "ASM SaaS" -> "Exposight" in docstrings, comments, `alembic.ini`, `pyproject.toml` description, `docs/`, `.agents/rules`. Kept: package `src/asm`, `asm` CLI, the distribution name `asm-saas` in `pyproject.toml` (renaming it changes the install name; ask first), and history in ENGINEERING_LOG.md. A test greps tracked files so the old name cannot come back.
3. **Deprecated APIs:** our routes use `status.HTTP_422_UNPROCESSABLE_ENTITY` 7 times; replace with the number `422` (the new name `HTTP_422_UNPROCESSABLE_CONTENT` does not exist in older Starlette that `fastapi>=0.115` allows). pytest turns any Starlette "'HTTP_...' is deprecated" warning into an error. `alembic.ini` gets `path_separator = os` (our config triggered Alembic's deprecation warning). Left and listed: `starlette.testclient` warning about `httpx` (raised inside `fastapi.testclient`).
4. **Local test DB:** `scripts/reset_test_db.py` drops and recreates the `_test` database and runs `alembic upgrade head` + `alembic check`. `tests/conftest.py` no longer calls `create_all`; it fails with a pointer to the script when the database is not at Alembic head. The CI browser job gets an `alembic upgrade head` step (it relied on `create_all`).
5. **Python 3.12:** full suite (DB + browser) in a scratch Python 3.12.12 venv (uv-managed interpreter exists locally).
- Not touched: dashboard delete buttons (Phase C), Caddy logging (Phase E).

### Phase D plan: DNS pinning + worker egress firewall (approved 2026-10-07 with D11-D16 below; D-1 first, D-2 after review)
Goal: close the DNS-rebinding / SSRF gap left by check-then-connect (`check_host_for_ssrf` docstring "Known limitation"). Two independent layers; either one alone stops a rebinding attack on the metadata endpoint, so a bug in one is caught by the other.

**Current state (read from code 2026-10-07):**
| Connection | Check | Connects to | Pinned? |
|---|---|---|---|
| prober `probe_host` -> `probe_url` (https + http, verified client) | `check_host_for_ssrf` (bool only, IPs discarded) | httpx resolves the hostname again | No |
| prober verify=False retry client | same check | httpx resolves again | No |
| prober redirect hop to a new host | `is_redirect_target_safe` (bool) | httpx resolves again | No |
| prober redirect hop to the same host | none (returns True) | httpx resolves again | No |
| headers_inspect step A (verified GET + hops) | `check_host_for_ssrf` in `run_inspection` | httpx resolves again | No |
| headers_inspect step D (unverified GET) | same | httpx resolves again | No |
| tls_inspect `connect_and_inspect_cert_socket` (headers_inspect step C) | `resolve_safe_ip`, own lookup | the validated IP, SNI = hostname (B-2) | **Yes** |
| portscan `scan_single_port` (16 ports) | `resolve_host_ips` + `is_safe_public_ip` in `scan_host_ports` | `asyncio.open_connection(hostname)`: up to 16 fresh lookups | No |
| discovery (crt.sh, Cert Spotter), SMTP, Supabase JWKS, TXT verification | operator-fixed hosts / DNS only | n/a | Not needed (not target-controlled) |

**Layer 1: DNS pinning (D-1 checkpoint)**
- Options: (a) rewrite the request URL to the IP, keep `Host: <hostname>` and pass httpcore's public `sni_hostname` request extension (httpx 0.28.1 / httpcore 1.0.9 installed; httpcore verifies the certificate against `sni_hostname`); (b) custom httpcore network backend mapping hostname -> IP (needs httpx private `_pool` or a re-implemented transport); (c) patch `socket.getaddrinfo` (process-wide, not thread-safe with the prober's thread pool). **Recommend (a)**: public API, per request, no global state.
- `scan_common`: one function `resolve_public_ips(hostname, resolver) -> (ips, reason)` returns the validated addresses (every address must be public, same fail-closed rules). `check_host_for_ssrf` and `tls_inspect.resolve_safe_ip` become thin wrappers so existing callers/tests keep working. `pick_ip(ips)` = first IPv4, else first IPv6 (D11). IPv6 connections are off unless `SCAN_IPV6_ENABLED=true` (default false, D12); a host whose validated addresses are all IPv6 while IPv6 is off is reported as `SKIPPED_IPV6_ONLY` (reason "IPv6-only host ...") by prober, portscan and inspect, never as unreachable or down. A skipped host has no findings, so change detection reports nothing for it (same as `SKIPPED_PRIVATE_IP`).
- `scan_common.pinned_request(url, ip) -> (wire_url, headers, extensions)`: builds `scheme://<ip or [ipv6]>:port/path?query`, `Host` header from the logical URL (port kept when non-default), `{"sni_hostname": hostname}` for https.
- prober: `probe_host` keeps the IP from the check; `_execute_single_url_probe` keeps a per-probe `{hostname: ip}` map. The logical URL (hostname) is used for `urljoin`, scope checks, `final_url` and the redirect chain; only the wire request uses the IP. A hop to a new host is resolved once by `is_redirect_target_safe` (changed to return the IP) and pinned; a hop to the same host reuses the stored IP (no new lookup). The verify=False retry uses the same map.
- headers_inspect: `run_inspection` passes the IP from its check into `inspect_single_host`; steps A and D pin the same way; step C passes the IP into `connect_and_inspect_cert_socket` (new optional `ip` argument) so the host is resolved once per stage, not twice.
- portscan: `scan_host_ports` passes the validated IP to `scan_single_port`, which calls `asyncio.open_connection(ip, port)`; the result still reports the hostname.
- Not changed: crt.sh, Cert Spotter, SMTP, JWKS (fixed hosts chosen by the operator), TXT verification (DNS only).
- Behaviour change: a multi-address host is contacted on one address only (today the OS may try others). Known ceiling, documented.

**Layer 2: worker egress firewall (D-2 checkpoint)**
- Options:
  - (A) Host rules on the VM: `DOCKER-USER` rules for the worker's source IP/bridge plus an `INPUT` rule (traffic from a container to the host's own addresses, e.g. the VCN private IP or the bridge gateway, goes through `INPUT`, not `FORWARD`, so `DOCKER-USER` alone misses it). Needs a static worker IP or a named bridge, boot persistence ordered before Docker, and care with Oracle's preinstalled `/etc/iptables/rules.v4`. Cannot be tested on Docker Desktop (Windows); only on the VM.
  - (B) Firewall-owned network namespace in compose: a tiny `egress` service (pinned `alpine` + `iptables`, `cap_add: NET_ADMIN`, built from `deploy/egress/`) joins `app-tier`, applies `OUTPUT` rules in its own namespace, then sleeps; the worker uses `network_mode: "service:egress"` and has no `NET_ADMIN`, so it cannot change the rules. Rules travel with the repo, work the same on Docker Desktop, CI and the VM, and cover host addresses too (`OUTPUT` sees every destination). Fails closed: if the rules script fails, `egress` exits, its healthcheck never passes and the worker never starts; if `egress` restarts, the worker loses its network until recreated (`depends_on: restart: true`).
  - (C) Egress proxy (e.g. Smokescreen): fits HTTP only; portscan and raw TLS sockets do not go through an HTTP proxy. Rejected.
- **Recommend (B)**, with (A) as an optional extra decided in D13.
- Rules (`deploy/egress/rules.sh`, `set -eu`), IPv4 `OUTPUT`: accept `lo` (Docker's embedded DNS at 127.0.0.11); accept `ESTABLISHED,RELATED`; accept tcp 5432 to the db service's fixed IP only (db gets static `ipv4_address: 10.89.0.10` in the existing app-tier subnet; correction 2026-10-07: never 5432 to any other private address; blocks worker -> api:8000/caddy); REJECT 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4; accept the rest. REJECT (not DROP) so a blocked connect fails fast instead of waiting out timeouts. IPv6 `OUTPUT`: accept `lo`, drop everything else (D12). The script ends by writing a marker file the healthcheck reads; the healthcheck also runs `iptables -C` on the 169.254.0.0/16 rule.
- DNS: Oracle's VCN resolver is 169.254.169.254, which the rules block. `egress` sets `dns: [1.1.1.1, 9.9.9.9]` (D14) so the worker never needs a link-local exception and the scanner sees the public view of target DNS.
- `compose.prod.yml`: new `egress` service; worker drops `networks:` and gets `network_mode: "service:egress"`, `depends_on: egress: {condition: service_healthy, restart: true}`. db/api/caddy unchanged.
- `scripts/egress_check.py` (stdlib only, runs inside the worker image): TCP connects and prints one line per target: `db:5432` must connect; another app-tier IP on 5432 (e.g. the api container's IP:5432) must be refused (proves the allow rule is the db IP only); `api:8000`, the bridge gateway, `169.254.169.254:80`, `10.0.0.1:22` and any public-internet IPv6 address must fail with refused/unreachable (not time out); `crt.sh:443`, `api.certspotter.com:443`, `1.1.1.1:443` and `$SMTP_HOST:$SMTP_PORT` (when set) must connect. Exit code non-zero on any mismatch.
- OCI note for DEPLOY.md: outbound port 25 is blocked by Oracle by default; SMTP must use 587/465.
- D-2 build details (2026-10-07, within the approved plan): app-tier gets `ip_range: 10.89.0.128/25` so Docker never hands a dynamic address that collides with the db's static 10.89.0.10; the db IP reaches `rules.sh` as `EGRESS_DB_IP` and a config test asserts both values match. Rejects use `icmp-admin-prohibited`, so a blocked connect fails with "No route to host" (EHOSTUNREACH) and `egress_check.py` can tell the firewall apart from a closed port (ECONNREFUSED); a blocked target only passes as BLOCKED, never as refused or timed out. The check is stdlib-only and runs through stdin (`docker compose exec -T worker python - < scripts/egress_check.py`), so the image is unchanged. Revert proofs run the same check from the worker image on `app-tier` without the firewall, delete single rules inside `egress` at runtime, and mount a rules script that exits halfway.

**Files to change**
- D-1: `src/asm/models.py` (new `SKIPPED_IPV6_ONLY`), `src/asm/scan_common.py`, `src/asm/prober.py`, `src/asm/headers_inspect.py`, `src/asm/tls_inspect.py`, `src/asm/portscan.py`; new `tests/test_d1_dns_pinning.py`; `docs/LEARNING_NOTES.md`; remove the "Known limitation" from the `check_host_for_ssrf` docstring.
- D-2: `compose.prod.yml`; new `deploy/egress/Dockerfile`, `deploy/egress/rules.sh`; new `scripts/egress_check.py`; `docs/DEPLOY.md` (new "Worker egress firewall" section: what it blocks, how to run the check, how to read failures, OCI DNS and port 25 notes, the Phase H checklist); `.github/workflows` (only if D15 = yes); README architecture line.
- Both: STATUS.md, ENGINEERING_LOG.md (one entry each), /terms only if it describes scanning safety (check, not expected).

**Test strategy**
- D-1 unit tests (no network, no DB):
  - Rebinding resolver stub: answers a public IP on the first query and `127.0.0.1` / `169.254.169.254` after; assert one resolution per host per stage and that every connection goes to the first answer.
  - httpx pinning: a local HTTPS server on 127.0.0.1 with a self-signed cert for `pinned.test`; the test allows 127.0.0.1 through `is_safe_public_ip` by monkeypatch only inside the test; the server records the `Host` header and the SNI name (`sni_callback`); assert `Host: pinned.test`, SNI `pinned.test`, and that cert verification is done against the hostname (a cert for another name fails verification).
  - Same for: a redirect to a new in-scope host (pinned to its own first answer), a redirect to the same host (no second lookup), the verify=False retry, headers_inspect steps A/C/D (one lookup, IP passed into the TLS fallback), portscan (`asyncio.open_connection` receives the IP for all 16 ports; patched to record).
  - `pinned_request` table test: IPv6 brackets, non-default port in `Host`, query string kept.
- D-1 revert proofs (each must fail on its own assertion): remove pinning in prober first hop; in redirect hops; in the retry client; in headers_inspect A; in D; drop the IP hand-off to the TLS fallback (lookup count 2 != 1); portscan back to hostname; `pick_ip` returning a private address from a mixed answer (all-public rule removed).
- D-2 local (Docker Desktop on Windows, and Linux CI if D15): `docker compose -f compose.prod.yml up -d --build`, then `docker compose exec worker python /app/scripts/egress_check.py` -> all lines OK. Proof that the check detects a hole, not just an offline host: `api:8000` is a real listener on a private address, so with the firewall removed (worker back on `app-tier`) the check must report `api:8000 CONNECTED (expected blocked)` and exit 1. Second revert: remove only the 10.0.0.0/8 rule -> same failure. Third: break `rules.sh` (`exit 1` mid-way) -> `egress` unhealthy, worker not started.
- Only on the real VM (Phase H): the real metadata endpoint (`curl -s -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/` works from the host, refused from the worker); the host's VCN private IP and sshd refused from the worker; Docker's embedded DNS works with the public resolvers; SMTP 587 delivery; crt.sh/Cert Spotter; whether the VCN has IPv6; the rules survive `docker compose restart egress`, `systemctl restart docker` and a reboot; the iptables backend inside the container (nft vs legacy) coexists with Docker's own rules; Oracle's preinstalled host rules do not block bridge traffic.

**Risks**
- `sni_hostname` is an httpcore extension: a future httpcore change could break verification silently. Mitigated by the local HTTPS test (fails if SNI/verification is not the hostname) and pinning `httpcore` minor range in pyproject (D16).
- Rules in the container namespace vs Docker's own NAT rules for 127.0.0.11: if the `iptables` backend in Alpine differs from the host's, both rule sets still apply, but listings are confusing. The check script tests behaviour, not listings.
- `egress` restart leaves the worker without network until it is recreated: fails closed (scans fail, nothing leaks); documented with the recovery command.
- Public resolvers (1.1.1.1, 9.9.9.9) become a dependency of scanning and alert delivery.
- Pinning to one address can turn a host with one dead address into "unreachable" (behaviour change, D11).
- REJECT messages show as connection refused in scan results only for attacker-shaped targets, which the app-level check already refuses first.

**Decisions D11-D16 (approved 2026-10-07)**
- **D11:** first IPv4, else first IPv6. A host with only IPv6 addresses while worker IPv6 is off is reported as skipped "IPv6-only" (`SKIPPED_IPV6_ONLY`), never as unreachable/down; tested.
- **D12:** worker IPv6 off (v6 OUTPUT drops all but `lo`); app side `SCAN_IPV6_ENABLED` default false.
- **D13:** compose namespace firewall (B) now; host `DOCKER-USER`/`INPUT` rules revisited in Phase H.
- **D14:** worker DNS 1.1.1.1 and 9.9.9.9.
- **D15:** add the CI job that builds the prod compose stack and runs `egress_check.py`.
- **D16:** cap `httpcore<2` in pyproject.
- **Correction (2026-10-07):** the Postgres allow rule is the db service's static IP on 5432 only; `egress_check.py` proves another private IP on 5432 is refused.

### Phase G plan: security scanners in CI (approved 2026-10-07: D17-D26 all as recommended, first option each)
Every tool was run locally once on HEAD `2c53a3e` before planning.

**Measured findings**
| Tool (version) | Scope | Findings | HIGH / CRITICAL |
|---|---|---|---|
| bandit 1.9.4 | `src/` (12,026 LOC) | 12: 2 HIGH, 2 MEDIUM, 8 LOW | 2 HIGH (B501) |
| pip-audit 2.10.1 | project deps resolved fresh; installed dev venv (44 pkgs); installed runtime image (32 pkgs) | 0 / 0 / 0 | none |
| gitleaks 8.30.1 | full history (`git` mode, 52 commits) | 8, all `generic-api-key` | all false positives (below) |
| trivy 0.75.0 | app image built from HEAD (Debian 13.7) | 211 OS: 51 HIGH, 85 MEDIUM, 67 LOW, 2 UNKNOWN; plus 5 MEDIUM + 1 LOW in `pip` 25.0.1 | 0 CRITICAL; 51 HIGH, **7 with a fix** |
| trivy 0.75.0 | egress image (`alpine:3.22.2`, from D-2) | 21 HIGH/CRITICAL with a fix | **2 CRITICAL + 19 HIGH, all fixable** (libcrypto3/libssl3 3.5.4-r0) |

bandit, each finding and its planned handling (no global skips; every `# nosec` names its test ID and carries a reason on the same line):
- B501 HIGH `prober.py:470`, `headers_inspect.py:321` (httpx `verify=False`): **justify.** Runs only after verification already failed, to report that a host serves an invalid certificate (`tls_valid=False`, `TLS_ERROR`). The request goes to the pinned, SSRF-checked IP, sends no credentials or cookies, and nothing from the response is trusted.
- B608 MEDIUM (low confidence) `db/roles.py:59, 76` (f-string DDL): **justify.** Role names cannot be bind parameters in DDL; every builder calls `validate_role_name` (`^[a-z_][a-z0-9_]*$` fullmatch) first; input is operator env, not user input.
- B311 LOW `verification.py:151, 166, 178`, `worker/worker.py:467, 1616` (`random` for jitter/backoff): **justify** (D21). Scheduling jitter, not a secret or token.
- B110 LOW `portscan.py:303` (writer close), `tls_inspect.py:175, 187` (certificate date parsing): **fix** (D22): catch the specific exceptions and log at debug instead of passing silently.

gitleaks, all 8 judged false positives (values inspected with masking):
- 5 in `tests/test_dashboard_ui.py` (commits `682df8e`, `51d6fd7`): `SUPABASE_PUBLISHABLE_KEY` / `data-supabase-key` = `anon_key_test_12345`, a test fixture string.
- 3 in `README.md` (commit `bf67c40`, lines 250/283/317): the documented example verification token `k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO` (visibly synthetic). Verification tokens are published in public DNS TXT records by design, so even a real one is not a secret.
- Handling: `.gitleaksignore` listing the 8 exact fingerprints (commit:file:rule:line), each preceded by a `#` comment with its reason. No rule disabled, no path allowlisted: a new key in the same files is still caught.

trivy, the 7 fixable HIGH in the app image: CVE-2026-75804 and CVE-2026-84782 (OpenSSL: `libssl3t64`, `openssl`, `openssl-provider-legacy` 3.5.7-1~deb13u2 -> u3) and CVE-2026-103111 (`libpcre2-8-0` 10.46-1~deb13u2 -> u3). A freshly pulled `python:3.12.14-slim-trixie` (created 2026-09-19, same digest) still has all 7. A scratch build adding `apt-get update && apt-get upgrade -y` to the runtime stage scanned clean (`--ignore-unfixed --severity HIGH,CRITICAL` exit 0) and still runs as `asm`. The other 44 HIGH have no fix (`affected` / `fix_deferred`: ncurses, systemd libs, util-linux, acl, perl-base); per the requested policy they do not fail CI and appear in the report. Egress image: `alpine:3.22.6` and `3.23.6` both scan clean; Dependabot's docker entry covers only `/`, which is why the D-2 pin went stale.

**Coverage (measured with `--cov=asm --cov-branch`; identical on Python 3.12.12 and 3.14.7)**
| Run | Tests | Lines | Line+branch (what `--cov-fail-under` checks) |
|---|---|---|---|
| no DB (CI `test` job today) | 475 passed, 228 skipped | 72.69% (3718/5115) | 70.30% |
| `pytest -m db` (CI `db-test` job today) | 238 | 62.70% | 58.47% |
| full non-browser suite with DB | 703 | 92.49% (4731/5115) | **90.48%** |
- Lowest modules (full run): `db/migration_guards.py` 50.0% (8 stmts), `worker/__main__.py` 69.6%, `tls_inspect.py` 83.2%, `worker/worker.py` 84.8%, `config.py` 85.1%.
- Plan: `db-test` runs the full non-browser suite (`pytest` with `TEST_DATABASE_URL`, a superset of `-m db`; nothing skipped or removed) with `--cov=asm --cov-branch --cov-fail-under=90` (floor of the measured 90.48%) and uploads the XML/HTML report as an artifact. Ratchet: raise the floor only by a deliberate change. The no-DB `test` job is unchanged.
- Build correction (2026-10-07): coverage compares at `precision = 2`. With the default precision 0, 90.63% rounds to 91 and passed `fail_under = 91` (and 90 really meant >= 89.5); found by the revert proof. pip-audit runs on `pip freeze --exclude-editable` with `--no-deps --disable-pip`, because `--strict` refuses the skipped editable project install.

**Planned CI** (D17: new `.github/workflows/security.yml`, on push/PR to main plus a weekly schedule; `ci.yml` keeps its jobs; the `egress-firewall` job is not touched)
- `bandit`: `bandit -r src -c pyproject.toml --severity-level low --confidence-level low`; fails on any finding without a justified `nosec`. A test asserts every `# nosec` in `src/` names a `B###` ID and has a reason.
- `pip-audit`: after `pip install -e ".[dev]"`, `pip-audit --strict --skip-editable` (installed runtime + dev set). Any finding fails; an unfixable one may only be ignored with `--ignore-vuln <ID>` plus a written reason.
- `gitleaks`: `actions/checkout` with `fetch-depth: 0`, then pinned `ghcr.io/gitleaks/gitleaks:v8.30.1 git --redact --exit-code 1` (no third-party action, no licence key; D25).
- `trivy`: build the app and egress images; scan each with pinned `aquasec/trivy:0.75.0 image --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1`, DB from `ghcr.io/aquasecurity/trivy-db:2` with `mirror.gcr.io` fallback and `--timeout 15m` (the default download timed out locally); a second non-failing run prints the full table.
- Coverage: `ci.yml` `db-test` as above (the only `ci.yml` change).
- README: keep the existing CI badge with `?branch=main`; add a Security workflow badge. No coverage badge (needs an external service; D26).

**Files to change**: `.github/workflows/security.yml` (new), `.github/workflows/ci.yml` (`db-test` step only), `.github/dependabot.yml` (docker entry for `/deploy/egress`), `pyproject.toml` (dev extras, `[tool.bandit]`, `[tool.coverage]`), `Dockerfile` (runtime `apt-get upgrade`, D18; optional `pip` removal, D23), `deploy/egress/Dockerfile` (alpine 3.22.6, D19), `.gitleaksignore` (new), `src/asm/prober.py`, `headers_inspect.py`, `db/roles.py`, `verification.py`, `worker/worker.py` (justified `nosec`), `portscan.py`, `tls_inspect.py` (B110 fixes), tests for `nosec` hygiene and B110 logging, README, docs/DEPLOY.md, SECURITY.md (scanner policy), STATUS, ENGINEERING_LOG.

**Proofs planned**: each gate shown failing once on a deliberate local mutation and passing after revert: bandit (remove one `nosec`), pip-audit (requirements file pinning a version with a known CVE), gitleaks (scratch repo with a fake AWS-style key committed), trivy (`alpine:3.22.2` exits 1), coverage (`--cov-fail-under=91` fails at 90.48%). Then tests with and without DB, browser, ruff.

**New dev dependencies (approval needed, D26)**: `bandit>=1.9.4,<2`, `pip-audit>=2.10.1,<3`, `pytest-cov>=7.1.0,<8` in `dev` extras. No runtime dependency. trivy and gitleaks run as pinned container images.

**Decisions D17-D26 (approved 2026-10-07, first option each)**
- **D17:** separate `security.yml` with weekly schedule (recommended), or jobs inside `ci.yml`.
- **D18:** app image OS fixes: `apt-get upgrade -y` in the runtime stage (recommended; fixes all 7 now; image content then depends on build date), or `--only-upgrade` of the named packages, or wait for a base refresh (security job red until then).
- **D19:** egress base `alpine:3.22.2` -> `alpine:3.22.6` (recommended, same minor) plus a Dependabot docker entry for `/deploy/egress`.
- **D20:** trivy scans both images (recommended), or only the app image.
- **D21:** B311 jitter: `# nosec B311` with reason (recommended), or switch to `secrets.SystemRandom()`.
- **D22:** B110: narrow exceptions + debug log (recommended), or `nosec` with reason.
- **D23:** remove `pip` from the runtime image after installing the wheel (clears 6 MEDIUM/LOW pip CVEs; nothing at runtime uses pip), or leave it.
- **D24:** coverage floor 90% line+branch on the full DB suite in `db-test` (recommended), or 70% on the no-DB job.
- **D25:** gitleaks via pinned container (recommended), or `gitleaks/gitleaks-action`.
- **D26:** approve the three dev dependencies; no coverage badge (or name a service).

### Phase E plan: cleanup checkpoint (requested 2026-10-07)
1. Distribution name `asm-saas` -> `exposight` in `pyproject.toml` (package `asm`, imports and the `asm` CLI unchanged); list every remaining `asm-saas`/`asm_saas` string; `tests/test_brand_text.py` stops allowing the old name line.
2. `src/asm/db/roles.py`: remove the two `# nosec B608`, run `bandit -r src -ll`; if bandit flags them, restore each with a one-line reason.
3. Full suite with `-W default`: list every distinct warning; fix those from our code; third-party ones listed only, no global suppression.
4. Caddy logging: report only (no config change), with two options for the owner to decide.
5. Decision (2026-10-07): Option A, Caddy access logs stay OFF (Caddyfile unchanged). Every service in `compose.prod.yml` gets json-file log rotation, max-size 10m, max-file 3 (one YAML anchor); a test asserts it; DEPLOY.md states both.

### Phase H-Azure-1 plan: block Azure platform endpoints for the worker (requested 2026-10-11)
1. `deploy/egress/rules.sh`: REJECT (icmp-admin-prohibited) 168.63.129.16/32, commented as the Azure WireServer / platform DNS.
2. `src/asm/scan_common.py` `is_safe_public_ip`: refuse 168.63.129.16/32 (also in IPv4-mapped/NAT64/6to4/compatible IPv6 forms), so a scan target resolving to it is refused before any connection; unit tests.
3. `scripts/egress_check.py`: `168.63.129.16:80` must be BLOCKED.
4. `tests/test_deploy_config.py`: the rule and the check target are required.
5. Worker DNS stays on 1.1.1.1 / 9.9.9.9 (`dns:` on `egress`), so blocking Azure's resolver does not break resolution.
6. `docs/DEPLOY.md`: "Azure" subsection (NSG inbound 22/80/443; WireServer blocked; IMDS answers from the host, BLOCKED from the worker).

### R-1 plan: route-complete tenant-isolation oracle + doc drift (review items E-3, E-6; requested 2026-10-11)
Tests and docs only; no file under `src/` changes; no new dependency (no Schemathesis).
1. New `tests/test_route_isolation_db.py` (marked `db`): enumerate every route from `asm.api.main.app.routes` at runtime (method + full path, included routers expanded); 40 application routes plus FastAPI's docs/openapi routes and the `/static` mount.
2. Explicit registry: every route is `TENANT_SCOPED`, `LIST_SCOPED` or `PUBLIC_OR_SELF` (the last with a one-line reason; a documented 403 also needs a reason). A meta-test fails on any route missing from the registry and on any registry entry with no route.
3. Every route with a tenant id in its path (TENANT_SCOPED and LIST_SCOPED): user B (owner of org B) calls it with org A's real ids, both as `/orgs/{org A}/...` and as `/orgs/{org B}/...` with A's domain/scan/invite/user id. Expect 404 (403 only where documented); no org-A marker string in the body; for POST/PUT/PATCH/DELETE, org A's rows (org, domains, scans, changes, notifications, memberships, invites, audit events) are unchanged.
4. Every LIST_SCOPED route: both tenants seeded (incl. invites and audit events); B's own list contains no org-A ids or markers, including `?domain_id=<org A domain>` on the audit-event routes (API and `/ui`).
5. `/ui/...` HTMX routes go through the same checks.
6. Any leak or cross-tenant write: stop, no fix, `xfail(strict=True)` with the reason, reported first as a security finding.
7. Revert proofs: drop one registry entry (meta-test must fail on that route); monkeypatch one tenant check open inside the test run only (a test must fail on the expected assertion). Both restored and passing.
8. Docs (E-6): README title and status describe the current product (multi-tenant ASM web app + worker + CLI) and phase (Phase H on Azure in progress), stale "Next" removed; STATUS marks Phase G (`605ca91`), Phase E (`354433f`) and H-Azure-1 (`3a6ab93`) committed; "## Next" updated. Any README number must match a command run in this checkpoint, else removed.

### E-1a plan: offline change-detection replay harness (review "Task 2"; requested 2026-10-12)
Measures how many false changes production change detection (P0) emits under scan noise. No file under `src/` or `migrations/` changes; no new dependency; P1/P2/P3 (k-of-n, re-probe) are not built, only described as gated next steps.
1. `experiments/change_replay/`: stage reports are built with the production report dataclasses in `asm.models` and their `to_dict()` (the same shapes the worker stores); the score report comes from `asm.scoring.score_domain_payloads(...).to_dict()` exactly as `asm/worker/runner.py::run_score` does, with `generated_utc` pinned for determinism.
2. Ground truth: one synthetic domain (12 hosts, some CDN-fronted), 30 scans, scripted labelled real events (new subdomain, subdomain removal, port open, port close, certificate rotation and issuer change, header removed, header added, stopped resolving).
3. Seeded noise classes, each with its own probability: `dns_timeout`, `dns_nxdomain`, `ct_partial` (silent subset, not truncated), `ct_truncated` (Cert Spotter fallback, truncated), `port_flap_filtered`, `port_flap_closed`, `cdn_edge` (other IP + other valid certificate), optional `probe_https_fail`, `inspect_timeout`.
4. Runner mirrors `asm/worker/worker.py::_perform_change_detection` (baseline = previous succeeded scan; `evaluate_removal_eligibility(base_disc, new_disc)` then `detect_changes(..., allow_removal=...)`), importing both from `asm.changes`.
5. Truth: a change is true if its key `(change_type, asset, detail)` is in the noise-free diff for the same scan pair, or matches a labelled real event not yet detected (delayed detection). Everything else is false. Metrics per noise class and combined: false changes per 1,000 asset-scans (by `change_type`), alert-eligible false changes (exposure, severity >= MEDIUM, the default `alert_min_severity`), missed real events, detection delay in scans.
6. `python -m experiments.change_replay.run --seed 1 --seeds 20` writes CSVs and `summary.md` to `experiments/change_replay/results/`; byte-identical on re-run (hashes compared).
7. `tests/test_change_replay.py` (no DB, no network): one seeded test per noise class at probability 1 pinning P0's exact behaviour; zero noise gives zero false changes and detects every event; the runner uses the production functions (identity check).
8. `EXPERIMENTS.md` at repo root: hypothesis, method, stop rule, threats to validity, reproduce command.

**Realistic noise profile (fixed before any result):** dns_timeout 0.01 and dns_nxdomain 0.002 per resolving host-scan; ct_partial 0.02 and ct_truncated 0.02 per scan (keeps 70-90% of names); port_flap_filtered 0.01 and port_flap_closed 0.005 per open port-scan; cdn_edge 0.10 per CDN host-scan; probe_https_fail 0.005 and inspect_timeout 0.005 per HTTPS host-scan. These are priors, not measurements.

**Stop rule (fixed before any result):** P0 is "negligible" and is kept, with no P1 work, if under the combined realistic profile, averaged over seeds 1-20, it emits <= 1.0 false change per 1,000 asset-scans AND <= 0.1 alert-eligible false change per 1,000 asset-scans AND misses 0 labelled real events. Any one bound exceeded means P1 is justified (still subject to approval).

### E-4 plan: domain-verification hardening (review item E-4; requested 2026-10-12)
Both processes run the DNS check: the api (`POST .../verification/check`, "Check now", `src/asm/api/routes.py`) and the worker (`reverify_due_domains`, `src/asm/worker/worker.py`). No DB migration (labels and values are derived from `Domain.name` and `verification_token`; nothing new is stored).
1. Label: new `_exposight-challenge.<domain>` with value `exposight-verify=<token>`. The checker also accepts the legacy `_asm-verify.<domain>` / `asm-verify=<token>` so domains verified under the old label do not lapse. `Domain.verification_record_name/value`, the dashboard, landing page, terms page and docs show only the new label; the legacy label/value exist only as checker constants in `asm.verification`.
2. Resolvers: the check queries explicit public resolvers from a new setting `VERIFICATION_RESOLVERS` (default `["1.1.1.1", "9.9.9.9"]`, at least two, each a public IP), built with `dns.resolver.Resolver(configure=False)` so the host/system resolver (on Azure 168.63.129.16, blocked for the worker) is never read or used. Queries set RD + AD and EDNS DO.
3. Decision per check: each resolver yields match (with or without AD), absent (NXDOMAIN / NoAnswer / no matching record at either label) or unknown (timeout, SERVFAIL, other DNS error). Any match with AD -> MATCH. Else all resolvers match -> MATCH; all absent -> ABSENT; anything else (a match/absent disagreement, or any unknown) -> UNKNOWN (no status change; may be propagation). `apply_check_outcome` and miss counting unchanged. Resolvers stay injectable (`resolvers=` parameter) so tests never touch the network.
4. Token validity: documented from the code (tokens never expire; rotated only by the rotate endpoint and `asm admin move-domain`) in docs/DEPLOY.md; /terms makes no claim about token lifetime, so it changes only for the label. Expiry enforcement and removal of the legacy label go to IDEAS.md.
5. Docs: egress image version references checked against `deploy/egress/Dockerfile`.
6. Tests (no network): new label match; legacy label match; AD match with one resolver; no-AD requires both; disagreement -> UNKNOWN; both absent -> ABSENT; timeout -> UNKNOWN; production path never builds a configured (system) resolver. Revert proofs: drop the legacy fallback (backward-compat test fails); accept a single non-AD match (requires-both test fails).

### H-Auth-1 plan: gate org creation for the invite-only demo (requested 2026-10-12)
Defence in depth next to Supabase "Allow new users to sign up" = OFF: today any confirmed Supabase account can `POST /orgs` and from there add domains, scan its own verified domains and send alert email.
1. Setting `ORG_CREATION_ALLOWED_EMAILS` (JSON list, default `[]` = nobody may create orgs); entries trimmed and lower-cased, each validated as an email address at startup.
2. `create_organization` (`routes_orgs.py`) returns 403 "Organization creation is limited to approved accounts..." unless the caller's email (trimmed, lower-cased) is listed; read through a FastAPI dependency so tests can override it. `POST /invites/accept` is unchanged, so non-listed users still join orgs by invite.
3. `compose.prod.yml`: pass-through for `api` (`${ORG_CREATION_ALLOWED_EMAILS:-[]}`), checked in `tests/test_deploy_config.py` like `VERIFICATION_RESOLVERS`.
4. Dashboard: `/ui/empty-org` renders the create-org form only for listed users; others see "ask an organization admin for an invite". No inline script, CSP unchanged.
5. Tests: listed user creates (201); non-listed 403; empty list blocks everyone; case/whitespace-insensitive match; non-listed user accepts an invite and lists that org; dashboard partial with and without the form; setting validation. Revert proof: remove the check, the 403 test fails.
6. Docs: fix DEPLOY.md "Signups may stay open"; invitee onboarding (operator creates the Supabase user with auto-confirm, then the org admin sends the invite token); `ORG_CREATION_ALLOWED_EMAILS` in DEPLOY.md and `.env.production.example`. IDEAS.md: alert_emails go to any address (rate limit or verified recipients later).

### H-Fix-1 plan: dev compose env, accept-invite form, doc fixes (requested 2026-10-12)
1. `docker-compose.yml`: `ORG_CREATION_ALLOWED_EMAILS` (api) and `VERIFICATION_RESOLVERS` (api and worker) with the app defaults; `tests/test_deploy_config.py` checks both compose files.
2. New partial `partials/accept_invite.html` (form `id="accept-invite-form"`, one token field), included in `empty_org.html` (new invitees land here) and in `domains_list.html` (members of another org land here). `app.js` submit handler calls `POST /invites/accept`; on success reloads the org list and selects the joined org; on error shows the API detail (403 wrong email, 404 invalid/expired/used, 409 already a member) in the global error box. No inline script; CSP unchanged. Tests: partial rendering; browser test: unlisted user pastes a valid token and sees the org, an invalid token shows the error. Revert proof: break the handler, the browser test fails.
3. Docs: STATUS marks E-4 (`0f4ca49`) and H-Auth-1 (`df6be35`) committed; DEPLOY.md suspension section says queued scans become `cancelled` ("Scanning is paused for this organization."); invitee onboarding uses the dashboard form.

### H-Deploy-1 plan: live-deploy docs + backup script mode (requested 2026-10-13)
1. `scripts/backup_db.sh` was committed as `100644`, so cron on the VM failed with "Permission denied". Set `100755` with `git update-index --chmod=+x`; `tests/test_deploy_config.py` checks the git index mode of every tracked `scripts/*.sh` (`git ls-files -s`), so a Windows checkout cannot drop it again.
2. DEPLOY.md: create `/opt/exposight` with `sudo mkdir` + `chown` before cloning; check Supabase Project Settings -> JWT Keys uses an ECC (P-256) or RSA current key, because the api accepts only ES256/RS256 and rejects the legacy HS256 secret; cron line uses `bash /opt/exposight/scripts/backup_db.sh` so it works even without the executable bit.
3. STATUS: "Live deploy 2026-10-13" entry with the VM verification results and what is not done yet.

### C-UI-1 plan: cinematic landing page (requested 2026-10-13)
Scope: `templates/landing.html`, `static/css/landing.css`, `static/js/landing.js`, a self-hosted font and the landing tests. Dashboard, API, auth and the CSP header are not touched.
1. Font: Space Grotesk variable woff2 (latin subset, OFL) under `static/fonts/` with its licence file; IBM Plex Mono (already self-hosted) for technical labels. Bold large headline with tight tracking and a gradient accent line.
2. Motion is CSS only: CSS 3D transforms (perspective, rotateX/Y, translateZ layers) and scroll-driven animations (`animation-timeline: view()/scroll()`) inside `@supports`, so browsers without support show everything static and fully visible. Reveal animations use no backwards fill, so off-screen content keeps opacity 1 (no-JS and no-support fallback). GSAP and ScrollTrigger are no longer loaded by the landing page (the vendored files stay; removing them is a separate step).
3. Hero: headline + primary CTA; the recon-pipeline card floats in 3D, its five stages light up in sequence under a scanning beam; receding grid and radar sweep behind it. "How it works": Add domain -> Verify (TXT) -> Scan -> Alert, pinned with `position: sticky` and driven by a named view timeline on wide screens; a plain list on narrow screens and without support. The required verification and audit-log copy stays word for word. Feature cards tilt in 3D on hover with a soft glow (`landing.js` sets two CSS custom properties with `style.setProperty`, pointer:fine only; CSS-only tilt without JS). Lucide icons inline as SVG (ISC licence, credited in a comment).
4. `prefers-reduced-motion: reduce` turns off every animation, the 3D tilt and the hover tilt.
5. Only true statements (facts from the code: CT-log discovery, ports 80/443 probing, 16 default ports, TLS and header checks, severity tiers, schedules 6-720 h, up to 5 alert recipients, append-only audit log, owner/admin/viewer roles).
6. Tests: the GSAP-specific browser tests are rewritten for the CSS version (same intent: 0 CSP violations, reduced motion = everything visible and untransformed, no-JS = everything visible, scroll reveals everything, CTA goes to /app). New: the landing page references no external origin (`src`/`href`/`url()`), the font is served from `/static/fonts/`, `landing.css` has a `prefers-reduced-motion` block. Before/after Playwright screenshots, desktop and mobile.

### C-UI-2 plan: restyle the landing page to DESIGN.md (requested 2026-10-13)
Spec: `DESIGN.md` (repo root, committed with this checkpoint by the owner). Its section 1 (hard rules) and sections 7/8 (approved copy / do-not-use) override everything else. Scope: `templates/landing.html`, `static/css/landing.css`, `static/js/landing.js`, `static/fonts/` and the landing tests. Dashboard, API, auth, CSP header and tool configuration are not touched.
1. Fonts: self-hosted latin-subset variable woff2 for Plus Jakarta Sans (headlines) and Inter (body), each with its OFL licence file; IBM Plex Mono stays for mono labels. Space Grotesk woff2 and licence removed. Total font payload reported.
2. Tokens from DESIGN.md: near-black neutrals, one cyan accent, severity colours for Critical to Info; 4/8 px radii; depth from tonal steps and 1 px borders.
3. Page order: header (Sign in primary) -> hero (status pill, headline with cyan phrase, true paragraph, decorative domain box linking to `/app`, three mono trust labels, the C-UI-1 3D pipeline card, and an "Example" panel with a CSS conic-gradient radar and an example scan feed) -> "From apex domain to exposed subdomains" (example topology + example inventory table) -> pinned "How it works" -> "What a scan checks" -> feature cards (change detection, scheduled scans, email alerts, audit log, tenant isolation, roles) -> ownership verification (TXT record format, resolver check) -> final CTA -> footer. Floating glass pill nav at the bottom centre; `landing.js` marks the active section with a class (IntersectionObserver, no inline styles); hidden below 480 px.
4. Example data uses only `example.com` names and documentation IPs (192.0.2.0/24, 198.51.100.0/24), is labelled "Example" and matches what the scorer would really report (for example MySQL 3306 with a banner -> Critical "Confirmed Exposed Database Service"; SMTP 25 -> Medium "Cleartext Protocol Service").
5. Every sentence checked against the code (`discovery.py` crt.sh + CertSpotter, `portscan.py` 16 ports, `prober.py` 64 KB, `headers_inspect.py`, `tls_inspect.py`, `scoring.py`, `verification.py` resolvers, `db/models.py` 6-720 h and 5 recipients, `routes_orgs.py` invite-only). Anything not confirmed is dropped.
6. Pinned "How it works" gap: the section is 400vh, so a full-page render shows about three viewports of empty dark space and the sequence has long stretches of dead scroll. Shorten the pin and retime the cards so one card is always in focus; new browser test scrolls the section in steps and fails if any frame has no card in focus or the section is taller than 3 viewports.
7. Motion system, reduced-motion and no-JS behaviour, CSP and the existing tests are kept; the radar sweep stops under reduced motion. Tests updated for the new fonts and sections. Before/after Playwright screenshots (desktop + mobile, scroll positions) in `output/c-ui-2-screenshots/`. Nothing committed.

### C-UI-4 plan: finish the theme (requested and approved 2026-10-14, with additions A and B)
Scope from the C-UI-4 inventory. Strict CSP string, routes' JSON contracts, auth and HTMX behaviour unchanged; no CDNs, no inline scripts or styles; test keys low-entropy.

**Found while planning:** an unhandled exception's 500 response carries no security headers at all (no CSP, no `X-Frame-Options`, no `nosniff`). FastAPI runs `@app.exception_handler(Exception)` in Starlette's outermost `ServerErrorMiddleware`, outside `add_security_headers_middleware`, so the H-Hdr-1 "every response" statement does not hold for 500s. Item 1 fixes it.

1. **Error pages (404, 403, 500).** New `templates/error.html` (standalone, `app.css`, radar logo, title, one short sentence, links to `/` and `/app`, `noindex`); it never echoes the path, the exception or any request data. A request gets the HTML page only when it is a *page request*: `Accept` contains `text/html` and the path is not under the API/partial prefixes `/orgs`, `/invites`, `/me`, `/health`, `/ui`, `/static`, `/docs`, `/redoc`, `/openapi.json`. Everything else keeps today's JSON (`{"detail": ...}` and the existing 500 body). In `main.py`: a `StarletteHTTPException` handler that renders the page for page-request 404/403 and otherwise delegates to FastAPI's default `http_exception_handler` (other statuses and headers such as `WWW-Authenticate` unchanged); the existing `Exception` handler renders the 500 page for page requests and keeps its JSON otherwise. Header logic moves from the middleware body into one function `_apply_security_headers(path, response, html)` that both the middleware and the 500 handler call, so headers stay defined in one place; HTML error pages get the full page CSP (`build_csp_header`), `nosniff`, `Referrer-Policy`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.
2. **/terms.** Header uses the landing `.brand` + `.brand-mark` radar logo (old `brand-badge` "EXP" span removed); only `landing.css` is loaded (the `app.css` link removed; `btn`/`btn-secondary` already exist in `landing.css`); new `.terms-content` (readable measure ~70ch, heading/list/paragraph spacing, `--text-muted` body, links) and `.terms-updated` (mono label) rules in `landing.css`. Terms text unchanged.
3. **Favicon.** `static/favicon.svg`: the radar mark (three circles, `#22D3EE` on `#09090B` rounded square), no script, no external refs. `<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">` in `landing.html`, `terms.html`, `base.html` (dashboard) and `error.html`. `/favicon.ico` is not added (browsers use the link; requests for it get the JSON/HTML 404 as above).
4. **og:image.** `static/og-image.png`, 1200x630, dark `--bg`, radar mark, "Exposight", the hero lines "Know every host you expose." / "Scan only what you own." (cyan), no numbers. Rendered once with Playwright from a scratch HTML page using the self-hosted fonts (generator kept out of the repo; size reported). `landing.html` and `terms.html`: `og:image` = `https://exposight.dev/static/og-image.png`, `og:image:width/height/alt`, `twitter:card` = `summary_large_image`, `twitter:image`.
5. **Landing "Open dashboard".** `landing.js`: inside `try/catch`, if any `sessionStorage` key matches `^sb-.+-auth-token$`, set the header `.landing-signin-btn` `textContent` to "Open dashboard" (`href` stays `/app`). Only key names are read; the value is never read or parsed; no fetch. No JS, no key, or a storage error: label stays "Sign in". Hero/CTA buttons unchanged.
6. **/app.** `base.html`: `<meta name="description">` and `<meta name="robots" content="noindex">` (base is used only by `app.html`).
7. **DESIGN.md.** New "Dashboard additions (C-UI-3/4)" section: token `--border-hover: #3F3F46` (input hover border; `app.css` uses the token instead of the literal), the AA chip text colours (Critical `#F87171`, Low `#60A5FA`, with the measured ratios and why), and the error-page/favicon/og-image notes. Existing landing rules unchanged.
8. **Test keys.** `tests/test_dashboard_ui.py` lines 43, 69, 122, 134, 158 -> `anon_key_1`. Already-committed history findings stay covered by the existing `.gitleaksignore` entries; local working-tree gitleaks scan rerun.
9. **Screenshots** to `output/c-ui-4-screenshots/` (gitignored), via a scratch Playwright script outside the repo (as in C-UI-3): scan detail (seeded succeeded scan with Fix first findings and changes) and alert history (seeded notifications), 1440 and 390 px; the 404, 403 and 500 pages, `/terms`, the landing header signed-in label, and the og-image itself.

**Files to change:** `src/asm/api/main.py`, `src/asm/templates/{base,landing,terms}.html`, new `src/asm/templates/error.html`, `src/asm/static/css/{app,landing}.css`, `src/asm/static/js/landing.js`, new `src/asm/static/favicon.svg`, new `src/asm/static/og-image.png`, `DESIGN.md`, `tests/test_dashboard_ui.py`, `tests/test_dashboard_css.py`, `STATUS.md`. `pyproject.toml` needs no change (`static/**/*` already packages the SVG and PNG).

**Tests to add:**
- `tests/test_cui4_error_pages.py`: page-request 404 (`/no-such-page`, `Accept: text/html`) is HTML with logo, links to `/` and `/app`, `noindex`, full page CSP, `X-Frame-Options`, `nosniff`, and does not contain the requested path; same path with `Accept: application/json` stays JSON; `/orgs/...`, `/ui/...`, `/static/missing.css` 404s stay JSON with `text/html`; 403 and 500 via the handlers called directly with a page request (HTML, generic text, no exception message, headers present) and an API request (JSON unchanged, headers present). No test-only route is added to `app` (the R-1 route meta-test would flag it).
- `tests/test_cui4_theme.py`: `/terms` loads only `landing.css`, has `.brand-mark`, no `brand-badge`; `landing.css` defines `.terms-content` and `.terms-updated`; favicon file is SVG without `<script>`/external refs, served as `image/svg+xml`, linked from `/`, `/terms`, `/app` and the 404 page; og-image is a PNG of exactly 1200x630 (IHDR) and `/`, `/terms` carry the absolute `og:image` and `summary_large_image`; `/app` has meta description and `robots noindex`; `landing.js` reads no storage values (`getItem` absent) and has no `fetch`.
- `tests/test_dashboard_css.py`: `#3F3F46` appears only as the `--border-hover` token value; DESIGN.md documents `--border-hover`, `#F87171`, `#60A5FA`.
- Browser (`tests/browser/test_dashboard_browser.py`): landing header shows "Open dashboard" when a `sb-test-auth-token` key is in `sessionStorage` (set before load with an init script; value is a dummy), "Sign in" without it, "Sign in" with JS disabled, "Sign in" and no page error when `sessionStorage` throws; no request leaves the origin; 0 CSP violations. Existing browser favicon 404 allowance stays.
- Revert proof per behaviour: page-request check removed (API 404 turns HTML), 500 headers call removed, `app.css` link back in terms, favicon link removed, og:image removed, landing.js key check removed, noindex removed.

Runs: full pytest with `TEST_DATABASE_URL`, browser tests, `ruff check .`, `bandit -r src -ll`, local gitleaks (Docker image). Nothing committed.

### H-Hdr-1 plan: clickjacking and Server-header findings from the live scan (requested 2026-10-14)
Two Low findings from the scan of exposight.dev. Found in code: `build_csp_header` already has `frame-ancestors 'none'`, but the middleware only sets the CSP on `/`, `/app*`, `/ui*`, `/static*` (and `/terms` sets it itself), so 404s and API/JSON responses carry no framing protection; nothing sets `X-Frame-Options`; uvicorn sends `server: uvicorn`; the `Dockerfile` entrypoint is `asm`, uvicorn is started only by `compose.prod.yml` and `docker-compose.yml`.
1. `add_security_headers_middleware` (the one place): `X-Frame-Options: DENY` on every response; responses outside the page paths (API, 404, docs) get `Content-Security-Policy: frame-ancestors 'none'` when they have no CSP, so the dev Swagger UI keeps working. The page CSP string is unchanged.
2. `--no-server-header` in the uvicorn `command` of both compose files (not the Dockerfile, which never runs uvicorn). Caddyfile site block: `header -Server` (Caddy's own `Server: Caddy` is removed too).
3. Tests: both headers on `/`, `/app`, `/terms` and a 404; compose args parsed with uvicorn's own CLI parser give `server_header=False`, and a live uvicorn started with that setting sends no `Server` header; Caddyfile test allows exactly HSTS and `-Server`.
4. Revert proof for each fix; full suite with `TEST_DATABASE_URL`, browser tests, ruff, bandit. Nothing committed.

### C-UI-3 plan: restyle the signed-in dashboard to DESIGN.md (requested 2026-10-14)
Visual change only. Scope: `static/css/app.css`, the header markup in `templates/app.html`, unused font files and the tests that name them. No change to routes, auth, permissions, HTMX attributes, `app.js`, element IDs, form fields or class names that templates/JS/tests use; CSP header unchanged.
1. `app.css` rewritten on the DESIGN.md tokens (dark neutrals, `--surface-2` cards, `--border`, cyan only for primary buttons, focus and active states). Fonts: Inter (body), Plus Jakarta Sans (panel titles), IBM Plex Mono (codes, chips), all already self-hosted; IBM Plex Sans woff2 files are no longer used by any page and are removed (tests updated).
2. Chips: status `verified`/`succeeded` green, `pending`/`lapsed`/`queued` amber, `failed` red, `running` cyan, `skipped`/`cancelled` neutral; severity `tier-critical`..`tier-info` from the DESIGN.md table (chip border = text colour at 35 %). Pill shape, mono label.
3. Header: dark `--surface-1` bar, the landing radar logo mark (inline SVG, no script) + "Exposight", org switcher, email, Sign out; wraps at 390 px.
4. Tables, inputs, code blocks, alerts, stage/score cards restyled; tables keep scrolling inside their container at 390 px. Contrast checked to WCAG AA. Only hover/focus transitions; none under `prefers-reduced-motion: reduce`.
5. Full pytest with `TEST_DATABASE_URL`, browser tests, `ruff check .`, `bandit -r src -ll`. Before/after Playwright screenshots (domain list, domain detail, scans list, audit log; 1440 px and 390 px) in `output/c-ui-3-screenshots/`. Nothing committed.

### Decisions D6-D9 (approved 2026-10-05)
- **D6:** `DELETE /me` while the user is an org's only owner: refuse with 409 naming those orgs; the user transfers ownership or deletes them first. No automatic tombstoning.
- **D7:** Exposight holds no Supabase `service_role` key, so `DELETE /me` cannot remove the Supabase login account. Documented in docs/DEPLOY.md and /terms; the operator deletes the Supabase identity on request.
- **D8:** retention periods: scans 180 days; sent or failed alert notifications 90 days; accepted, revoked or expired invites 30 days; audit events never purged automatically. Keep the latest successful scan and any baseline scan.
- **D9:** purge off by default (`RETENTION_PURGE_ENABLED=false`), admin dry run checked before enabling in production.

## Next
- Finish Phase H (deployment on Azure): the public domain is pending.
- E-1: E-1a replay harness done (P0 not negligible under the assumed noise); next measure real noise rates, then P1/P2/P3 only with approval (EXPERIMENTS.md).
- E-3: done by checkpoint R-1 (`tests/test_route_isolation_db.py`).
- E-7: drills.

## Skills Plan
- **Installed**: Docker (x4: `docker-build-strategies`, `docker-compose-patterns`, `docker-destructive-guardrails`, `docker-project-foundations`), `arena`, `frontend-design`, `webapp-testing`, `security-and-hardening`, GSAP (x6: `gsap-core`, `gsap-performance`, `gsap-plugins`, `gsap-scrolltrigger`, `gsap-timeline`, `gsap-utils`).
- **Later (each only when its phase starts)**:
  - `greensock/gsap-skills`: v3.5 landing page.
  - `coreyhaines31/marketingskills` or `claude-seo`: only if launching publicly.
  - `remotion-dev/skills`: demo video.

## Known Limitations
- DNS lookup during manual check runs while holding the domain database row lock (sequential, up to 2 labels x 3s per configured resolver: about 12s with the default two).
- Integration test suite requires PostgreSQL (SQLite is unsupported for DB tests).
- Only the table owner role (`exposight_owner`) can disable the audit_events append-only trigger; the app role cannot. Retention purge is off by default (D9); denied requests not logged.
- Rate limits are in-memory and single-process (`--workers 1`); counters reset on api restart.
- Invite tokens are returned to the inviter to share; Exposight does not email them.
- Deletion is API-only (`DELETE /me`, `DELETE /orgs/{id}`); the dashboard has no delete buttons yet.

### D-1 review checkpoint (2026-10-07)
- IMPLEMENTED: preserved and reviewed the existing DNS-pinning increment; added six private-redirect refusal cases and made missing certificate-fallback pins fail on an explicit assertion.
- VERIFIED in this session (Python 3.14.7): full dedicated-test-DB suite 698 passed, 19 deselected; browser suite 17 passed, 700 deselected; final targeted D-1 suite 25 passed; `ruff check .` clean; `git diff --check` clean apart from line-ending notices.
- VERIFIED: eight negative controls in an isolated scratch copy each failed on the intended assertion: first probe request, redirect request, TLS retry, inspection primary request, inspection retry, certificate fallback pin, port connection, and mixed public/private DNS answers. Original repository code was never mutated for these controls.
- Remaining known warning: Starlette TestClient deprecation for httpx (pre-existing, outside D-1).
- PLANNED next approved increment: D-2 worker egress firewall, following the reviewed D-1 checkpoint. D-2 is not implemented by this checkpoint. No claim of VM, deployment, CI, Python 3.12 or complete EXPO gate verification is made by this local run.

### E-1a Port, Inspection & Discovery Consistency Consolidation (2026-10-15)
- IMPLEMENTED:
  - Port observation validity: OPEN and CLOSED are definite observations; FILTERED, timeout, missing results, and unprobed hosts are unknown. Traverses up to 3 successful prior scans for latest definite state. Accurate per-change `baseline_scan_run_id` attribution.
  - HTTPS inspection observation validity: Decoupled certificate and header validity. Per-field header evidence tracking (`_find_latest_header_observation`, `_find_latest_hsts_strength` requiring prior presence before `SECURITY_HEADER_REMOVED`, prior strong before `SECURITY_HEADER_WEAKENED`, prior missing before `SECURITY_HEADER_ADDED`).
  - Certificate defect completeness & remediation: Affirmative proof requirement (`_is_defect_remediated`) before defect resolution. Identity-only partial certificates cannot resolve defects. Restored established `if ... elif ...` rotation policy (issuer before not_after; no event multiplication).
  - CT discovery consistency: Transition-based change detection across a bounded history window (up to 3 prior scans).
    - Scan-level gate vs per-host qualification: `evaluate_removal_eligibility` checks only source matching and non-truncation (it does not itself check for non-empty results). Non-empty results are evaluated per-host in `_is_qualifying_absence`.
    - Per-host anchor-source comparability: absences qualify only in non-empty, non-truncated reports matching the source of the host's most recent observed presence (`anchor_source`).
    - Consecutive absence confirmation: requires 2 consecutive qualifying absences before emitting `REMOVED_SUBDOMAIN`.
    - Single emission on entry into confirmed absence; continued absence does not re-emit.
    - Rediscovery after confirmed absence emits `NEW_SUBDOMAIN` referencing the confirmed absent scan.
    - Transient noise recovery (1-scan omission or interrupted by unknown/fallback) suppresses duplicate `NEW_SUBDOMAIN`.
    - First observed hostname within available history emits `NEW_SUBDOMAIN` immediately.
    - Clean separation between discovery membership and DNS resolution transitions (`NEWLY_RESOLVING`, `STOPPED_RESOLVING`).
  - Worker first-scan vs. pure detector contract:
    - Pure detector (`detect_changes`) emits `NEW_SUBDOMAIN` for all assets against empty input bundles.
    - End-to-end worker contract (`ASMWorker._perform_change_detection` and `_mark_run_final`) explicitly treats the first successful domain scan as a baseline (`status="baseline"`, `baseline_scan_run_id=None`, `changes=[]`, `removal_detection="skipped"`); bypasses alert generation completely, queues zero change-based notifications, and writes zero rows to `scan_changes`.
  - Synthetic alert eligibility clarification: Replay benchmark "alert eligibility" indicates that a change meets the policy filter (`category == "exposure"` and severity >= MEDIUM), but does not establish that an actual email was delivered to an external recipient (which depends on worker dispatch rules, domain subscription settings, and live SMTP transport).

### E-1a Bounded HTTPS-Loss Confirmation Checkpoint (2026-10-15)
- IMPLEMENTED:
  - Bounded confirmation policy for HTTPS reachability loss (`HTTPS_LOST`):
    - Contract-based classification (`_classify_https_probe_observation`):
      - `SUCCESS`: Host affirmatively `PROBED` and HTTPS endpoint reachable.
      - `QUALIFYING_FAILURE`: Host affirmatively `PROBED`, HTTP answers (`http.reachable is True`, matching `HTTP_NO_HTTPS` finding contract), and HTTPS failed with a definite error (`CONNECT_ERROR` or `TLS_ERROR`).
      - `UNKNOWN`: Any missing host entry, non-`PROBED` status (`SKIPPED_UNTRUSTED`, `SKIPPED_PRIVATE_IP`, `SKIPPED_UNRESOLVED`, `SKIPPED_NOT_HTTPS`, `SKIPPED_IPV6_ONLY`), transient network timeout (`TIMEOUT`), redirect loop (`TOO_MANY_REDIRECTS`), unclassified error (`OTHER`), or general host outage (`http.reachable is not True`).
    - Confirmation conditions:
      - Requires two consecutive qualifying failures ($S_0$ and $S_1$).
      - Requires previously observed successful HTTPS reachability within the bounded 3-prior-scan window ($S_2$ or $S_3$). If never observed or expired from history, no confirmed transition is fabricated.
      - Single emission on entry into confirmation; subsequent failures ($S_0=F, S_1=F, S_2=F, S_3=\text{SUCCESS}$) are suppressed as already confirmed.
      - Successful HTTPS reachability resets the loss sequence.
      - Inconclusive or unknown observations reset the failure streak.
      - References actual prior successful scan in `baseline_scan_run_id`.
      - Describes transition as repeated observed reachability failure while HTTP remains responsive, not proof that the owner disabled HTTPS.
- VERIFIED (Offline):
  - 95/95 offline tests passed across `tests/test_change_detection.py` (79 passed) and `tests/test_change_replay.py` (16 passed).
  - Regressions cover: success -> fail -> success (0 loss events); success -> fail -> fail (1 loss event with baseline to success); success -> fail -> fail -> fail (0 duplicates); success -> unknown -> fail -> fail (confirms with baseline to success); success -> fail -> unknown -> fail (0 loss events); missing/skipped/blocked observations (treated as unknown); never-observed and expired success; recovery followed by new sustained loss; HTTP_NO_HTTPS prerequisites and TLS_ERROR; worker first-scan baseline contract; and distinguishing supported 1-unknown sequences from expired 2-unknown sequences.
  - Supplemental replay test `test_candidate_sustained_https_loss_detected_with_deliberate_delay` proves genuine sustained failure is detected at scan $T+1$ (1-scan delay), emits 1 event with historical baseline, and suppresses duplicates on subsequent scans.
  - Linter: `ruff check src/ tests/ experiments/` passed with 0 errors.
  - `git diff --check`: clean (0 whitespace/CRLF issues).
  - Seeded benchmark candidate replay (20 seeds, 7,080 asset-scans):
    - Archived candidate artifacts in distinct directory `experiments/change_replay/results_port_inspect_discover_probe/` (also preserved in `results_candidate/`).
    - `probe_https_fail`: false changes dropped from 69 (9.75/1k) down to 41 (5.79/1k). Spurious `HTTPS_LOST` dropped from 28 to **0**. Alert-eligible false changes dropped from 28 (3.95/1k) to **0 (0.00/1k)**.
    - `combined`: false changes dropped from 660 (93.22/1k) down to 636 (89.83/1k). Spurious `HTTPS_LOST` dropped from 24 (3.39/1k) to **0**. Alert-eligible false changes dropped from 30 (4.24/1k) down to **6 (0.85/1k)** (all 6 remaining alert-eligible false changes are from `port_flap_closed`).
    - Missed events: 1 in `combined` (Seed 12 `cert_rotated` under `cdn_edge`, unchanged).
    - Detection delays: mean delay 0.14 scans, max delay 1 scan.
- BOUNDED-HISTORY LIMITATIONS, DELIBERATE DELAY & BLIND SPOTS:
  - Deliberate confirmation delay: Requiring 2 consecutive qualifying failures introduces an intentional 1-scan delay for genuine sustained HTTPS failures (detected at the 2nd failed scan rather than the 1st).
  - Bounded 3-scan window expiration:
    - Supported: `SUCCESS(t) -> UNKNOWN(t+1) -> FAILURE(t+2) -> FAILURE(t+3)`. At $t+3$, history is $[F(t+2), U(t+1), S(t)]$; $S(t)$ is within the 3-prior-scan window, confirming loss with baseline pointing to $S(t)$.
    - Expired: `SUCCESS(t) -> UNKNOWN(t+1) -> UNKNOWN(t+2) -> FAILURE(t+3) -> FAILURE(t+4)`. At $t+3$ (1st failure), streak=1 so no confirmation. At $t+4$ (2nd failure), history is $[F(t+3), U(t+2), U(t+1)]$; $S(t)$ occurred 4 scans ago and has expired from the 3-prior-scan window, so no `HTTPS_LOST` transition is emitted.
  - Inconclusive observation blind spot: If a host experiences timeouts (`TIMEOUT`), redirect loops (`TOO_MANY_REDIRECTS`), unclassified errors (`OTHER`), or full host outages (`http.reachable is False`), the observation is classified as `UNKNOWN` and resets the failure streak rather than confirming an HTTPS loss.
- REMAINING FAILED STOP-RULE CRITERIA:
  - False changes per 1,000 <= 1.0: FAIL (current 89.83/1k, driven by 41.24/1k CDN cert changes and 19.92/1k port flap changes).
  - Alert-eligible false per 1,000 <= 0.1: FAIL (current 0.85/1k, driven entirely by 6 `PORT_NEWLY_OPEN` from `port_flap_closed`).
  - Missed real events <= 0: FAIL (1 missed event: Seed 12 `cert_rotated` under `cdn_edge`).
- PENDING & PARKED WORK:
  - Database Integration & Migration Verification (Verified on isolated disposable PostgreSQL 18.6 container):
    - Full migration sequence verified: `alembic upgrade head` (14 migrations) -> `alembic check` (0 drift) -> `alembic downgrade -1` -> `alembic upgrade head` all exited 0.
    - Targeted database suites (32 passed, 0 failed in 5.77s):
      - `tests/test_change_detection_db.py`: 10 passed, including multi-scan history window & domain isolation, per-change distinct baseline persistence, subdomain removal lifecycle ($P \to A \to A \to A$), and HTTPS loss lifecycle ($S \to F \to F \to F$).
      - `tests/test_alerts_db.py`: 8 passed, including atomic outbox writes in fenced transaction and alert min_severity filtering.
      - `tests/test_b3_change_type_compat_db.py`: 3 passed.
      - `tests/test_b5_deletion_retention_db.py`: 11 passed, including multi-baseline retention protection.
    - Full non-browser test suite with database and coverage gate: **940 passed, 27 deselected, 0 failed** in 85.50s.
    - Coverage gate passed: **90.57% total coverage** (exceeds pyproject.toml `fail_under = 90.0%`).
    - Linter and formatting: `ruff check .` (0 errors), `git diff --check` (clean).
    - Narrow cleanup: disposable PostgreSQL container cleanly stopped and removed with zero residual volumes or state.
  - Overall release acceptance remains pending: 6 alert-eligible `PORT_NEWLY_OPEN` false alerts from synthetic port flap noise remain an unresolved tradeoff; stop-rule bounds are not met.
  - Preserved distinct archives: `results/` (original P0 benchmark), `results_port/`, `results_port_inspect/`, `results_port_inspect_discover/`, and `results_port_inspect_discover_probe/`.
  - Parked product work preserved: C-UI-5 dashboard redesign plan (parked in STATUS.md awaiting approval).

### Viewer-Privacy Consistency Fix Checkpoint (Completed 2026-10-15)
- **Policy:**
  - Viewers may inspect domain configuration and alert outbox history, but must not receive configured alert-recipient email addresses (`alert_emails`, `recipient`) or raw delivery errors (`last_error`).
  - Admins and owners retain full unredacted access.
- **Contract & Schemas (`src/asm/api/schemas.py`, `src/asm/db/models.py`):**
  - `DomainRead`: `alert_emails: list[str] | None = None` distinguishes unconfigured (`[]` for admin) from redacted (`None` for viewer). Added `alert_recipient_count: int` (backed by `@property alert_recipient_count` on `Domain` ORM model) so viewers know recipient counts without disclosing addresses.
  - `AlertNotificationRead`: `recipient: str | None = None` and `last_error: str | None = None` (redacted to `None` for viewers).
- **Server-Side Serialization (`src/asm/api/routes.py`, `src/asm/api/routes_ui.py`):**
  - Explicit role-aware helpers `_domain_to_read(domain, role)` and `_notification_to_read(notification, role)` enforce redaction during response model instantiation based on authenticated `Membership.role`. Never trusts client-supplied roles.
  - SQLAlchemy model instances are never mutated (zero dirty-session writes or cross-request pollution).
  - Routes updated:
    - `GET /orgs/{org_id}/domains`: returns `list[DomainRead]` (redacted for viewers).
    - `GET /orgs/{org_id}/domains/{domain_id}`: returns `DomainRead` (redacted for viewers).
    - `POST /orgs/{org_id}/domains`: returns `DomainRead`.
    - `PUT /orgs/{org_id}/domains/{domain_id}/schedule`: returns `DomainRead`.
    - `PUT /orgs/{org_id}/domains/{domain_id}/alerts`: returns `DomainRead`.
    - `GET /orgs/{org_id}/domains/{domain_id}/alert-notifications`: returns `list[AlertNotificationRead]` (redacted for viewers across all pagination offsets/limits and status filters).
    - UI routes: `GET /ui/orgs/{org_id}/domains/{domain_id}` and `GET /ui/orgs/{org_id}/domains/{domain_id}/alert-notifications` pass role-aware serialized representations to Jinja templates for defense-in-depth.
- **Verification on Isolated Disposable PostgreSQL 18.6 Container:**
  - Created disposable container `exposight-privacytest-c7e1f9a2b4d8` using `postgres:18.6-alpine` on loopback `127.0.0.1:50873`, with tmpfs on `/var/lib/postgresql`, zero persistent mounts or volume leaks.
  - Migrated from scratch: all 14 Alembic migrations applied to head cleanly.
  - Dedicated test suite `tests/test_viewer_privacy_db.py` (5 passed in 0.77s):
    - Viewer vs admin vs outsider (404) on lists, details, and notification history.
    - Pagination (`limit`, `offset`) and status filters (`?status=failed`) maintain strict redaction.
    - Zero synthetic email addresses or raw SMTP errors leaked in viewer payloads.
    - Database verification: viewer reads do NOT persist `None` back into PostgreSQL or pollute subsequent admin reads.
    - UI verification: viewer sees `"2 recipients configured"` with recipient forms and columns hidden.
  - Regression verification against database:
    - `tests/test_alerts_api.py`: 4 passed (0.70s).
    - `tests/test_tenant_isolation.py`: 9 passed (1.13s).
    - `tests/test_dashboard_ui.py`: 37 passed (1.54s).
    - `tests/test_route_isolation_db.py`: 84 passed (8.94s).
    - `tests/test_alerts_db.py`: 8 passed (1.60s).
    - `tests/browser/test_dashboard_browser.py`: 24 passed (62.20s).
  - Clean container destruction: stopped and removed with `docker rm -f`.
- **Preservations & Remaining Stop-Rules:**
  - Preserved all scanner fixes, benchmark archives, and parked C-UI-5 work.
  - No deployment, push, or production access.
  - Release stop-rules remain pending: 6 residual alert-eligible port flap false alerts remain an unresolved tradeoff; remote CI and Azure live deployment remain user-reported and unverified.

### Discovery Resource-Limit Checkpoint (Completed 2026-10-16)
- **Ingestion & Response Body Bounds (`src/asm/discovery.py`):**
  - Response body streaming byte budget (`DISCOVERY_MAX_RESPONSE_BYTES`, default provisional 10 MiB) enforced chunk-by-chunk before JSON parsing on both crt.sh and Cert Spotter. Content-Length header checked before streaming when present.
  - Rejection of non-identity `Content-Encoding` before body consumption across all HTTP statuses (success and error paths), closing responses immediately and following provider fallback/error semantics.
  - Cert Spotter cumulative budget (`CumulativeBudget`): charges consumed response-body chunks inside reading loop across pages, retries, and error bodies. Preserves accounting if socket iteration raises `ReadTimeout` or transport errors; retries never reset the budget.
  - Error preview bounding: `_read_error_text_bounded` retains and decodes only up to its configured preview allowance (e.g. 8,192 bytes) even when the underlying transport yields a single chunk larger than the allowance (e.g. 64 KiB), while charging total consumed bytes to the cumulative budget and closing the response.
  - Transport chunk distinction: documented that with `chunk_size=None`, transport chunk size is governed by socket/framing buffers and is not an application-defined numeric constant.
  - Resource claim correction: removed unsupported fixed 3–5× JSON memory multiplier; parsing overhead depends on JSON structure (object vs string density) and has not been empirically measured.
- **Hostname Selection & Downstream Protection (`src/asm/discovery.py`):**
  - Hostname cap (`DISCOVERY_MAX_HOSTS`, provisional default 1,000) applied deterministically in `select_bounded_subdomains` (prioritizing discovered apex, then sorted alphabetically) after normalization and scope filtering, before DNS resolution or downstream scanning.
  - Truncation metadata: `truncation_reason` ("hostname_cap_exceeded", "provider_entry_limit", "provider_and_hostname_cap_exceeded") recorded in discovery report counts (`selected_hosts`, `observed_hosts`). Prevents downstream false subdomain removal events.
  - UI disclosure: scan-detail UI displays partial-coverage notices in pipeline stages for active and historical reports.
  - Configuration validation: `_validate_positive_int` strictly rejects non-integers (strings, floats, booleans) and non-positives with `DiscoveryConfigurationError`. CLI discovery remains self-contained without requiring database or auth configuration.
- **Scan Detail Route Optimization & Contract Fidelity (`src/asm/api/routes_ui.py`, `tests/test_scan_detail_route_db.py`):**
  - `get_org_scan_detail_ui` queries `ScanResult` filtering `stage.in_(["discover", "score"])`, excluding heavy `portscan` rows from DB transfer.
  - Test suite uses real terminal lifecycle status `"succeeded"` (no invented `"completed"` statuses).
  - Uses representative production `ScoreReport` schema (`domain_score`, `domain_band`, `hosts` with `findings`, `domain_findings`).
  - Observed executed SQL via SQLAlchemy `before_cursor_execute` cursor listener, asserting stage restriction and parameter binding (`discover`, `score` present, `portscan` excluded).
  - Verified ORM identity map exclusion (`port_res not in db_session`), HTML finding rendering, and multi-tenant 404 anti-enumeration boundaries.
- **Targeted Verification Scope (Disposable PostgreSQL 18.6 Instance):**
  - Note: Verification was targeted to affected discovery and scan-detail route tests; does not represent full repository test suite (940+ tests) or live production/Azure verification.
  - Created disposable cluster via `initdb` on temp directory (`pg_asm_disp_8921`), started daemon on loopback `127.0.0.1:5433`, migrated with `scripts/reset_test_db.py` (14 migrations to head, 0 drift).
  - Test execution: **86 passed, 0 failed in 0.70s**:
    - `tests/test_discovery.py`: 80 passed (streaming budget accounting, large single-chunk preview retention, non-identity encoding rejection across 200/400/404/429/500/502, argument validation, hostname selection).
    - `tests/test_scan_detail_route_db.py`: 6 passed (SQL cursor interception, ORM loading exclusion, truncation notices, tenant isolation).
  - Hygiene: `uv run ruff check .` clean (0 errors), `git diff --check` clean (0 warnings).
  - Isolation & cleanup: postgres daemon terminated via task kill, port 5433 freed (0 connections), temp data directory removed (`Test-Path` returned False).
- **Preservations:**
  - Preserved all previous scanner changes, viewer privacy protections, frozen replay benchmark archives (`experiments/change_replay/`), and parked C-UI-5 work.
  - No deployment, push, live provider requests, dependency changes, or production access.

### Combined Local Verification Milestone (Completed 2026-10-16)
- **Status:** Accumulated changes passed the reported local verification suite; working tree remains uncommitted. Remote CI, production verification and replay acceptance remain unresolved.
- **Verification Scope:**
  - Migration sequence: `alembic upgrade head` (14 migrations) -> `alembic check` (0 drift) -> `alembic downgrade -1` -> `alembic upgrade head` -> `alembic check` (all exit 0).
  - Full non-browser test suite with coverage: **1,008 passed, 0 failed, 28 deselected** in 68.96s.
  - Branch & line coverage: **90.82%** (exceeds pyproject.toml 90.0% requirement).
  - Full Playwright browser regression suite: **26 passed, 0 failed** in 76.49s.
  - Linter & git diff: `ruff check .` (0 errors), `git diff --check` (0 warnings).
  - Attributable defect fixed: removed CSP-violating inline `style` attribute from `scan_detail.html` truncation notice and defined `.stage-card-notice` in `app.css`.
  - Disposable environment: executed against ephemeral Docker PostgreSQL 18.6 container (`exposight-verify-c8491d9e7a2b`) on loopback 127.0.0.1:5433 with tmpfs mount, verified via unique database identity marker `exposight_verify_marker_f92b71d4c82e`. Cleanly destroyed after run.

### Independent Review Remediation Backlog & Prober Content-Encoding Checkpoint (2026-10-18)
- **Durable Backlog**: Recorded in `docs/REVIEW_REMEDIATION_BACKLOG.md` against baseline `09e813794dab61e1a81b3cc555e90fd33848fc6b`, separating Group 1 (HTTP decompression/resource limits), Group 2 (Frontend async session/org races), Group 3 (Inventory pruning, definite-DNS history, bootstrap, capacity, replay parity), Group 4 (Worker verification-loss & owner lifecycle), Group 5 (Viewer-access policy & operator reason redaction), and Group 6 (Operational hardening observations), with corrected Seed 79 (`api.example.com:5432` scan-19/20), `REMOVED_SUBDOMAIN` (`severity="INFO"`, non-alerting), and `domain_subdomains` schema/capacity (`subdomain`, `status`, `consecutive_qualifying_absences`, `removed_at_scan_run_id`, `max_active_subdomains=5000`, `max_tombstones=1000` in `detect_changes` / `ASMWorker._execute_change_detection` / `ASMWorker._mark_run_final`) notes.
- **Prober Bounded Response & Content-Encoding Policy (`src/asm/prober.py`, `tests/test_prober.py`)**:
  - `_has_non_identity_content_encoding` inspects `Content-Encoding` header tokens across both comma-separated values and repeated header lines via `response.headers.get_list("content-encoding", split_commas=True)`.
  - When any non-identity `Content-Encoding` is present, `_stream_and_read_body` closes the response immediately and returns `b""` without invoking `httpx` decompression or passing compressed bytes to `extract_title`, while `_execute_single_url_probe` preserves `reachable=True`, HTTP status, response headers (`server`, `x_powered_by`, `content-type`), redirect handling, and TLS status.
  - Uncompressed streaming responses read raw wire chunks via `response.iter_raw(chunk_size=4096)` (and already-consumed responses slice `response.content[:MAX_BODY_BYTES]`, with no `iter_bytes` fallback or mock detection), retaining at most `MAX_BODY_BYTES` (`64 KB`) and closing the response in `finally:` on completion, truncation, rejection, or exception. (`MAX_BODY_BYTES` bounds the retained body buffer, not underlying socket/transport buffer allocations.)
