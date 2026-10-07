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
  - B-5 committed (`ae5cd34`): `DELETE /orgs/{id}` (owner) deletes domains (cascading to scans, changes, notifications), memberships and invites and keeps the org row as a `deleted-org-<id>` tombstone with its audit log (`org.deleted` event); 409 while a scan in the org is running, queued scans and schedules cancelled in the same transaction; `DELETE /me` deletes the account, its memberships and invites to its email, one `account.deleted` event per org, 409 naming the orgs while the user is a sole owner (D6), 403 when suspended (deletion requests then go to the operator); the Supabase identity is deleted by the operator on request (D7). Retention purge (D8: scans 180 d keeping each domain's latest successful scan and change baselines, sent/failed notifications 90 d, closed invites 30 d, audit never) in `asm.retention`; worker runs it hourly only with `RETENTION_PURGE_ENABLED=true` (default false, forwarded in compose.prod.yml); `asm admin purge --dry-run | --execute` (D9). /terms, README, DEPLOY.md updated. Tests: 666 passed (non-browser, with DB), 444 passed + 222 skipped without `TEST_DATABASE_URL`, 17 browser passed.
  - B-6 committed (`ba26c4f`): scans cancelled by suspension or org deletion are stored as `cancelled` with a neutral reason ("Scanning is paused for this organization." / "The organization was deleted."); the dashboard shows a grey "Cancelled" badge and a "Scan cancelled" note; retention treats `cancelled` as finished; migration 0014 rewrites the two old "Cancelled: ..." rows shapes and its downgrade restores them. Docker tag and remaining "ASM SaaS" text now Exposight (distribution name `asm-saas` kept). Our 7 uses of `HTTP_422_UNPROCESSABLE_ENTITY` replaced with `422`; pytest fails on any Starlette "'HTTP_...' is deprecated" warning; `alembic.ini` sets `path_separator = os`. `scripts/reset_test_db.py` rebuilds the local test DB with Alembic; the `db_engine` fixture no longer runs `create_all` and fails unless the DB is at Alembic head; the CI browser job runs `alembic upgrade head`. Tests: 673 passed (non-browser, with DB), 445 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; same counts under Python 3.12.12.
- v3.6c Phase D (plan in Plans & Decisions):
  - D-1 reviewed and verified (2026-10-07): DNS pinning. Prober (both schemes, every redirect hop, unverified retry), header inspection (steps A and D), the TLS certificate fallback and all port connects use the IP that passed the SSRF check, resolved once per host per stage; hostname kept for `Host`, SNI and certificate verification (`scan_common.pin_host` / `pinned_request`, httpcore `sni_hostname`). First IPv4 else IPv6 (D11); IPv6 off unless `SCAN_IPV6_ENABLED=true` (D12), IPv6-only hosts reported as `SKIPPED_IPV6_ONLY`; `httpcore>=1.0,<2` (D16). Tests: 694 passed (non-browser, with DB), 466 passed + 228 skipped without `TEST_DATABASE_URL`, 17 browser passed; 12 revert proofs caught.
  - D-2 (worker egress firewall): after review of D-1.

## Plans & Decisions
Plans are written here and approved before coding starts.

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

### D-1 review checkpoint (2026-10-07)
- IMPLEMENTED: preserved and reviewed the existing DNS-pinning increment; added six private-redirect refusal cases and made missing certificate-fallback pins fail on an explicit assertion.
- VERIFIED in this session (Python 3.14.7): full dedicated-test-DB suite 698 passed, 19 deselected; browser suite 17 passed, 700 deselected; final targeted D-1 suite 25 passed; `ruff check .` clean; `git diff --check` clean apart from line-ending notices.
- VERIFIED: eight negative controls in an isolated scratch copy each failed on the intended assertion: first probe request, redirect request, TLS retry, inspection primary request, inspection retry, certificate fallback pin, port connection, and mixed public/private DNS answers. Original repository code was never mutated for these controls.
- Remaining known warning: Starlette TestClient deprecation for httpx (pre-existing, outside D-1).
- PLANNED next approved increment: D-2 worker egress firewall, following the reviewed D-1 checkpoint. D-2 is not implemented by this checkpoint. No claim of VM, deployment, CI, Python 3.12 or complete EXPO gate verification is made by this local run.
