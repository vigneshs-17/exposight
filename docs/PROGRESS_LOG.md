# Exposight Remediation Queue Progress Log

## Item 0: Safety + Baseline & PR #26
- **Status**: Completed & Merged (PR #26 merged into `main` at `e26ec63261779547016e7b2a5b1f11266c1d80aa`)
- **Baseline Replay**: 80 seeds (28,320 asset-scans), 1,278 total false changes (45.13 / 1,000), 35 alert-eligible (1.24 / 1,000), 1 missed event (Seed 79 port_closed). Seed 43 subdomain_removed recovered at scan 14. Documented in `docs/benchmarks/BASELINE_e26ec63261779547016e7b2a5b1f11266c1d80aa.md`.
- **Limits**: Preserved all existing workspaces, lockfiles, notes, benchmark labels, and noise gates.

## Item 1: Test Portability for Scheduler Tests
- **Status**: Completed & Merged (PR #27 merged into `main` at `bb6d62f6d36a92bed65479c84cf3cf83a8f33db8`)
- **Failing Before / Passing After**: `tests/test_scheduler.py::test_schedule_enable_from_null_sets_next_scan_at_now`, `tests/test_scheduler.py::test_schedule_change_existing_interval_advances_next_scan_at`.
- **Fix**: Replaced `.replace(tzinfo=UTC)` with `.astimezone(UTC)` when timezone offset is present, eliminating spurious 5.5h offsets on non-UTC local environments without weakening time boundary assertions.

## Item 2: G4 Worker & Owner Lifecycle
- **Status**: Completed & Merged (PR #28 merged into `main` at `81702fbeaa1a8a29b472eecaa4da1d6bb4a2d829`)
- **Failing Before / Passing After**:
  - `tests/test_worker_lifecycle_db.py::test_g4_1_verification_loss_during_exception_cancels_run_instead_of_requeueing`
  - `tests/test_worker_lifecycle_db.py::test_g4_2_stranded_queued_scans_cancelled_on_revocation_and_unblocks_unique_scan`
  - `tests/test_worker_lifecycle_db.py::test_g4_3_last_active_owner_guards_disallow_demotion_removal_and_deletion`
  - `tests/test_worker_lifecycle_db.py::test_g4_4_inventory_select_error_fails_scan_without_fabricating_absence`
  - `tests/test_worker_lifecycle_db.py::test_g4_finalization_after_authorization_loss_keeps_evidence_and_blocks_notifications`
- **Fix**:
  - G4.1: `_handle_unexpected_worker_exception` cancels runs permanently when domain verification is lost instead of requeueing unclaimable jobs. Stale unverified leases cancelled during lease reclamation.
  - G4.2: Joined `User` and filtered `User.suspended_at.is_(None)` in `update_member_role`, `remove_organization_member`, and `delete_my_account` to prevent last-active-owner bypass. Added `cancel_queued_scans_for_domain` during operator revocation, override expiry, and DNS reverification lapse to prevent stranding `uq_scan_runs_active_domain`.
  - G4.3: Checked domain verification and active owner status under domain lock in `_mark_run_final`. When authorization is lost, marked `failed`, preserved already-collected stage evidence in `scan_results`, and suppressed inventory transitions and alert rows.
  - G4.4: Removed broad exception swallowing around `domain_subdomains` `SELECT`; DB errors propagate and fail the scan attempt instead of fabricating absence or corrupting inventory.

## Item 3: G5.1 Operator Verification Reasons Privacy
- **Status**: Completed & Merged (PR #29 merged into `main` at `3131020f0654259bdac154ae353874c3e2c537d5`)
- **Failing Before / Passing After**: `tests/test_viewer_privacy_db.py::test_g5_1_operator_verification_reasons_redacted_for_viewers_and_notifications_db`.
- **Fix**: Redacted/hid operator verification reasons from viewer roles in `_domain_to_read` and `_domain_to_verification_read` (returning `None` for viewers while keeping raw reasons for owner/admin). Applied `redact_sensitive_text` to operator reason in `admin.py` `cancel_queued_scans_for_domain` and `queue_domain_alert` outbox notifications, and added defense-in-depth body redaction in `_notification_to_read` for viewers. Updated OpenAPI schema descriptions in `DomainRead`, `DomainVerificationRead`, and `AlertNotificationRead`.
- **Limits**: Kept raw reasons for owner/admin in DB and API responses; preserved audit log role isolation (viewers receive HTTP 403 on `/audit-events`).

## Item 4: G3.4 Capacity Check Ordering & Truncation Separation
- **Status**: Completed & Merged (PR #30 merged into `main` at `266a5be838b58a32c3f89e9f097342936cef05cc`)
- **Failing Before / Passing After**: `tests/test_change_detection.py::test_g3_4_capacity_check_ordering_vs_same_scan_removals_and_separate_truncation_metadata`.
- **Fix**: Reordered change detection in `src/asm/changes.py` so Section 2b removals run before Section 2a additions, immediately freeing active slots for new hosts or reappearances occurring within the same scan. Separated inventory capacity metadata (`inventory_capacity_exceeded = True`, `untracked_subdomains_count = len(untracked_subdomains)`) from upstream CT provider truncation, eliminating mutation of provider `truncated=True` or `truncation_reason` so downstream absence tracking is not corrupted. Updated `routes_ui.py` to display inventory cap warnings independently from provider truncation, and updated `worker.py` persistence check.
- **Limits**: Preserved `max_active_subdomains = 5000` limit, deterministic tombstone retention, and provider truncation semantics.

## Item 5: G2 Frontend Asynchronous Session / Organization Races
- **Status**: Completed & Verified in Worktree `D:\exposight-g2-wt`
- **Failing Before / Passing After**:
  - `tests/browser/test_g2_frontend_races_browser.py::test_g2_1_request_path_org_vs_header_mismatch_browser`
  - `tests/browser/test_g2_frontend_races_browser.py::test_g2_2_action_continuation_delayed_response_after_org_switch_browser`
  - `tests/browser/test_g2_frontend_races_browser.py::test_g2_2_action_continuation_delayed_response_after_logout_browser`
  - `tests/browser/test_g2_frontend_races_browser.py::test_g2_3_load_org_switcher_delayed_after_logout_browser`
  - `tests/browser/test_g2_frontend_races_browser.py::test_g2_3_401_refresh_retry_delayed_after_org_switch_browser`
- **Fix**:
  - G2.1: Derived `X-Origin-Org-Id` in `htmx:configRequest` from the request URL org ID path (`/^\/ui\/orgs\/(\d+)\//`) before falling back to `currentSelectedOrgId`. In `htmx:beforeSwap`, dropped swap if either `pathOrgId` or `reqOrgHeader` mismatches `currentSelectedOrgId` or if they disagree, eliminating header-shadowing and cross-org DOM contamination.
  - G2.2: Guarded all async action continuations in forms (`#create-org-form`, `#accept-invite-form`, `#add-domain-form`, `#schedule-settings-form`, `#alerts-settings-form`) and buttons (`#btn-check-verification`, `#btn-rotate-token`, `#btn-run-scan`) by capturing `(startEpoch, startOrgId)` and checking `currentSessionEpoch === startEpoch && isAuthenticated && String(currentSelectedOrgId) === String(startOrgId)` after every `await authenticatedFetch` and `await resp.json()`.
  - G2.3: Guarded `loadOrgSwitcher` after `await authenticatedFetch('/orgs')` and `await resp.json()`. In `htmx:responseError`, guarded post-refresh retry against session epoch changes, sign-out, or org switches away from `pathOrgId`. Guarded `authenticatedFetch` against session epoch changes across `refreshSession`.
- **Limits**: Preserved server-side RBAC and session token validation (client headers never grant backend access).

## Item 6: G3.5 Replay / Production Parity
- **Status**: Completed & Verified in Worktree `D:\exposight-g35-wt`
- **Failing Before / Passing After**:
  - `tests/test_change_replay.py::test_g3_5_replay_candidate_runs_production_persistent_inventory`
  - `tests/test_change_replay.py::test_g3_5_replay_candidate_parity_with_adapter`
  - `tests/test_change_replay.py::test_g3_5_replay_candidate_passes_positive_scan_ids_and_production_allow_removal`
  - `tests/test_change_detection.py::test_g3_5_effective_domain_band_uses_persisted_inventory_beyond_lookback`
- **Fix**: Replaced legacy 3-scan lookback candidate in `experiments/change_replay/harness.py::replay_candidate` with production persistent inventory discovery (`bootstrap_persistent_inventory`, positive monotonic scan IDs, production `allow_removal = not truncated and not empty`). Unified `adapter_persistent_discovery.py` to delegate directly to `replay_candidate`, achieving 100% parity across all 80 benchmark seeds (1,278 total FC, 35 alert-eligible, 1 miss). Sourced active domain hosts in `src/asm/changes.py::_effective_domain_band_and_score` directly from `persisted_inventory` when available, preserving active host risk score bands beyond the 3-scan window.
- **Limits**: Preserved baseline noise gates and benchmark ground-truth definitions.

## Item 7: Scanner Gates ADR and Reversion of PR #33 Relaxation
- **Status**: Completed & Verified in Worktree `D:\exposight-revert-gates-wt`
- **Failing Before / Passing After**: `tests/test_change_replay.py::test_scanner_benchmark_gates_adr_alignment`.
- **Fix**: Reverted the improper gate relaxation introduced in PR #33. Restored invariant owner stop-rule gates: `MAX_ALERT_FALSE_PER_1000 = 0.1` and `MAX_MISSED = 0`. Removed the hard failure gate on informational (non-alert) false changes, reporting the rate honestly as diagnostic telemetry. Documented the owner's decision word-for-word in `docs/adr/0001-scanner-benchmark-gates.md` and `docs/decisions/0001-scanner-benchmark-gates.md`. Preserved prober resource-safety hardening (G1.1 streaming 64 KB body cap via `response.iter_raw(chunk_size=4096)`, non-identity `Content-Encoding` rejection, G1.2 TLS timeout alignment within 10s deadline, G1.3 deterministic `response.close()` cleanup in `finally:`).
- **Limits**: Honest reporting without relaxing quality gates; real event recall and alert-eligible false change thresholds remain strictly invariant.

## Final batch Item 2: Docker Log Rotation
- **Status**: Already on `main` before this batch; no change needed.
- **Evidence**: every service in `compose.prod.yml` uses the `x-logging` anchor (json-file, `max-size: 10m`, `max-file: 3`); `tests/test_deploy_config.py::test_every_service_has_log_rotation` enforces it.

## Final batch Item 3: RFC 9116 security.txt
- **Failing Before / Passing After**: `tests/test_security_txt.py` (2 of 3 failed with 404 before the route existed).
- **Fix**: `GET /.well-known/security.txt` in `src/asm/api/routes_ui.py`, `text/plain`, Contact = GitHub private advisory URL, rolling `Expires` 180 days ahead (always under the RFC one-year limit), `Preferred-Languages: en`, `Canonical`. Route classified PUBLIC in the route-isolation registry.
- **Limits**: no PGP signature; Canonical is the fixed `https://exposight.dev` URL.

## Final batch Item 4: /privacy Page
- **Failing Before / Passing After**: `tests/test_privacy_page.py` (6 tests; all failed before: 404 and missing footer links).
- **Fix**: `templates/privacy.html` on the landing theme (only `landing.css`, no scripts or inline styles): stored data, processors (Supabase, Microsoft Azure, crt.sh, Cert Spotter, public DNS resolvers, the email provider), invite-only student beta, GitHub advisory contact. Retention days are rendered from `asm.retention` constants, so the page cannot drift from the purge code. Footer links on landing, terms and the dashboard (`.app-footer` in `app.css`). Route classified PUBLIC.
- **Limits**: the page says the purge is off unless the operator enables it; whether production enabled it is not visible to the app.

## Final batch Items 5-9: Owner Setup Docs
- **Item 5** `docs/EMAIL_SETUP.md`: confirmed the worker reads `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_STARTTLS`, `SMTP_SSL`, `SMTP_TIMEOUT` (`src/asm/worker/worker.py`). Brevo on `notify.exposight.dev`, port 587 STARTTLS, credentials only in the VM `.env`, one test send through `send_smtp_email` inside the worker container.
- **Item 6** `docs/DNS_RECORDS.md`: apex CAA (`letsencrypt.org`, `issuewild ";"`), SPF `-all`, DMARC `p=reject`; `notify` keeps its own SPF/DKIM/DMARC so the apex policy does not block it.
- **Item 7** `docs/BACKUP_SETUP.md`: age key on the laptop, public key at `/etc/exposight/backup_age_recipient.pub`, root cron 03:30 UTC, weekly PowerShell `scp`, restore test into a throwaway container. Restore commands drilled locally against PostgreSQL 18.6 with the production role layout.
- **Item 8** `docs/MONITORING_SETUP.md`: UptimeRobot HTTP(s) check on `/health` with email alert; notes that `/health` does not cover the worker.
- **Item 9**: `CERTSPOTTER_API_KEY` Bearer support was already on `main` (`tests/test_discovery.py::test_certspotter_api_key_sent_as_bearer_and_not_leaked`); no code change. Terms question recorded as P-1 in `docs/DECISIONS_PENDING.md`.
- **PRs**: #40 (item 3), #41 (item 4), #42 (items 5-9), all 12 CI checks green before each merge.

## Final batch Item 1: DEPLOY_NEXT.md Rewrite
- **Target**: `main` at `36248a3957774a0946931a184c955d7bd04fb34c` (includes #40-#42); VM corrected to `Standard_B2als_v2`, x86_64.
- **Fix**: pre-deploy `backup_db.sh` + PowerShell `scp` to `D:\exposight-backups\`; `git pull --ff-only`; `up -d --build` with `migrate` as a service; `alembic_version` read through the db container's own `$POSTGRES_USER`/`$POSTGRES_DB`; post-deploy egress check, headers, `/health`, `security.txt`, `/privacy`, worker, one manual scan of `exposight.dev`.
- **Rollback**: restore into a dropped and recreated database (owner and grants as `10-roles.sh`), never on top; code-only rollback only when `0015` was not applied; `0015` downgrade refuses on populated `domain_subdomains` by design. Drop/recreate/restore drilled locally on PostgreSQL 18.6.

## Final batch Item 10: Repo Hygiene (report only)
- Nothing deleted. Recommendations are in the final batch report to the owner.
