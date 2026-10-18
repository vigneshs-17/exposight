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

