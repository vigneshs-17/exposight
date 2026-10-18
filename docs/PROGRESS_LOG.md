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
- **Status**: Completed & Verified in Worktree `D:\exposight-g4-wt`
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
