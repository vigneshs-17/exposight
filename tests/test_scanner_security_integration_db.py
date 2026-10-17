"""Real PostgreSQL integration tests for scanner authorization and outbound-safety hardening.

Tests exercise real database transactions, row locking, and status transitions against PostgreSQL.
External network calls (DNS, HTTP sockets, SMTP) are strictly mocked.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.admin import all_owners_suspended, revoke_verification, suspend_user
from asm.api.routes import queue_scan
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanResult,
    ScanRun,
    ScanStage,
    User,
)
from asm.db.scans import UnverifiedDomainError, enqueue_scan
from asm.worker.runner import IScannerRunner
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


class MockStageRunner(IScannerRunner):
    """Mock scanner runner returning deterministic stage reports without network access."""

    def __init__(self) -> None:
        self.invoked_stages: list[str] = []

    def run_discover(self, domain: str) -> dict[str, Any]:
        self.invoked_stages.append("discover")
        return {"domain": domain, "results": [{"subdomain": f"api.{domain}"}]}

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        self.invoked_stages.append("probe")
        return {"domain": domain, "results": []}

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        self.invoked_stages.append("portscan")
        return {"domain": domain, "results": []}

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        self.invoked_stages.append("inspect")
        return {"domain": domain, "results": []}

    def run_score(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        self.invoked_stages.append("score")
        return {"domain": domain, "domain_score": 10, "counts": {}}


def _create_org_with_owner(
    session: Session, name: str, is_suspended: bool = False
) -> tuple[int, uuid.UUID]:
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        email=f"{name.lower().replace(' ', '')}@example.com",
        suspended_at=datetime.now(UTC) if is_suspended else None,
        suspended_reason="Policy test" if is_suspended else None,
    )
    session.add(user)
    session.flush()

    org = Organization(name=name)
    session.add(org)
    session.flush()

    membership = Membership(org_id=org.id, user_id=user.id, role="owner")
    session.add(membership)
    session.flush()
    session.commit()
    return org.id, user_id


# ==============================================================================
# 1. Verification Records (Expired, Future-Expiring, Non-Expiring)
# ==============================================================================


def test_expired_operator_override_cannot_enqueue_in_database(clean_db, db_engine):
    """An expired operator override in PostgreSQL cannot be enqueued manually or scheduled."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "Expired Org")
        domain = Domain(
            org_id=org_id,
            name="expired-override.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) - timedelta(hours=2),
            scan_interval_hours=24,
            next_scan_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # Direct database enqueue must reject
    with Session(db_engine) as session:
        with pytest.raises(UnverifiedDomainError):
            enqueue_scan(session, domain_id, trigger="manual")

    # API queue_scan must reject with 422
    with Session(db_engine) as session:
        mock_response = MagicMock()
        membership = session.scalar(select(Membership).where(Membership.org_id == org_id))
        org_obj = session.get(Organization, org_id)
        with pytest.raises(HTTPException) as exc_info:
            queue_scan(
                org_id=org_id,
                domain_id=domain_id,
                auth_context=(org_obj, membership),
                db=session,
                response=mock_response,
            )
        assert exc_info.value.status_code == 422

    # Scheduler must skip and not create any scan runs
    worker = ASMWorker(engine=db_engine)
    worker.schedule_due_scans(batch_limit=10)
    with Session(db_engine) as session:
        scans = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain_id)).all()
        assert len(scans) == 0


def test_future_expiring_and_non_expiring_domains_enqueue_successfully(clean_db, db_engine):
    """Active operator overrides and non-expiring DNS TXT verifications enqueue normally."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "Active Org")
        future_domain = Domain(
            org_id=org_id,
            name="future-override.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        txt_domain = Domain(
            org_id=org_id,
            name="txt-verified.example.com",
            verification_status="verified",
            verification_method="dns_txt",
            verification_expires_at=None,
        )
        session.add_all([future_domain, txt_domain])
        session.commit()

        run1 = enqueue_scan(session, future_domain.id, trigger="manual")
        run2 = enqueue_scan(session, txt_domain.id, trigger="manual")
        run1_id = run1.id
        run2_id = run2.id
        session.commit()

        r1 = session.get(ScanRun, run1_id)
        r2 = session.get(ScanRun, run2_id)
        assert r1.status == "queued"
        assert r2.status == "queued"


# ==============================================================================
# 2. Expiry Transitions (Between Enqueue & Execution, and Between Stages)
# ==============================================================================


def test_expiry_between_enqueue_and_execution_fails_persisted_run(clean_db, db_engine):
    """If verification expires after enqueueing, run fails before execution."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "MidExpiry Org")
        domain = Domain(
            org_id=org_id,
            name="mid-expiry.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

        # Simulate expiry before worker claims the job
        domain.verification_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    mock_runner = MockStageRunner()
    worker = ASMWorker(engine=db_engine, runner=mock_runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "failed"
        assert "verification is not active" in (run_record.error or "")
        stages = session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()
        # All stages must be skipped; zero stages executed
        assert all(st.status == "skipped" for st in stages)
        assert len(mock_runner.invoked_stages) == 0


def test_expiry_between_stages_stops_pipeline_and_skips_remaining(clean_db, db_engine):
    """If verification expires between stages, stage fails and remaining stages are skipped."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "BetweenStages Org")
        domain = Domain(
            org_id=org_id,
            name="between-stages.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    class ExpiringStageRunner(MockStageRunner):
        def run_discover(self, domain: str) -> dict[str, Any]:
            res = super().run_discover(domain)
            # Expire the domain immediately after discover completes
            with Session(db_engine) as s:
                d = s.get(Domain, domain_id)
                d.verification_expires_at = datetime.now(UTC) - timedelta(seconds=10)
                s.commit()
            return res

    runner = ExpiringStageRunner()
    worker = ASMWorker(engine=db_engine, runner=runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "failed"
        assert "Domain verification lapsed/revoked" in (run_record.error or "")

        stages = {st.stage: st.status for st in session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()}
        assert stages["discover"] == "succeeded"
        assert stages["probe"] == "skipped"
        assert stages["portscan"] == "skipped"
        assert stages["inspect"] == "skipped"
        assert stages["score"] == "skipped"
        # Outbound probe, portscan, inspect were never executed
        assert runner.invoked_stages == ["discover"]


# ==============================================================================
# 3. Organization Suspension (All Owners Suspended vs. At Least One Active)
# ==============================================================================


def test_suspension_matrix_active_owner_vs_all_suspended(clean_db, db_engine):
    """Scans allowed if >=1 owner active; blocked if all owners suspended."""
    with Session(db_engine) as session:
        org_id, owner1_id = _create_org_with_owner(session, "MultiOwner Org")
        owner2_id = uuid.uuid4()
        owner2 = User(id=owner2_id, email="owner2@example.com")
        session.add(owner2)
        session.flush()
        session.add(Membership(org_id=org_id, user_id=owner2_id, role="owner"))

        domain = Domain(
            org_id=org_id,
            name="multi-owner.example.com",
            verification_status="verified",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # Suspend owner 1 only -> owner 2 is still active
    with Session(db_engine) as session:
        suspend_user(session, str(owner1_id), "First owner suspended")
        assert all_owners_suspended(session, org_id) is False

    # Enqueue scan must succeed because owner 2 is active
    with Session(db_engine) as session:
        run = enqueue_scan(session, domain_id, trigger="manual")
        run_id = run.id
        session.commit()
        assert session.get(ScanRun, run_id).status == "queued"

    # Suspend owner 2 as well -> all owners now suspended
    with Session(db_engine) as session:
        suspend_user(session, str(owner2_id), "Second owner suspended")
        assert all_owners_suspended(session, org_id) is True

    # API queue_scan must now return 403 Forbidden
    with Session(db_engine) as session:
        mock_response = MagicMock()
        membership = session.scalar(select(Membership).where(Membership.org_id == org_id))
        org_obj = session.get(Organization, org_id)
        with pytest.raises(HTTPException) as exc_info:
            queue_scan(
                org_id=org_id,
                domain_id=domain_id,
                auth_context=(org_obj, membership),
                db=session,
                response=mock_response,
            )
        assert exc_info.value.status_code == 403
        assert "Scanning is paused" in exc_info.value.detail


def test_zero_owner_organization_is_not_treated_as_suspended(clean_db, db_engine):
    """An organization without owners does not falsely trigger suspension."""
    with Session(db_engine) as session:
        org = Organization(name="ZeroOwner Org")
        session.add(org)
        session.commit()
        assert all_owners_suspended(session, org.id) is False


# ==============================================================================
# 4. Unexpected Exception Retry vs Suspension Cancellation
# ==============================================================================


def test_unexpected_worker_exception_cancels_run_if_org_suspended(clean_db, db_engine):
    """Unexpected worker exception cancels run and stages if org is suspended."""
    with Session(db_engine) as session:
        org_id, owner_id = _create_org_with_owner(session, "RetrySuspended Org")
        domain = Domain(
            org_id=org_id,
            name="retry-suspended.example.com",
            verification_status="verified",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    # Claim the run manually into 'running'
    claim_token = uuid.uuid4()
    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        run_record.status = "running"
        run_record.claim_token = claim_token
        run_record.claimed_by = "test-worker"
        run_record.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
        # Mark discover stage as running
        stage = session.scalar(
            select(ScanStage).where(
                ScanStage.scan_run_id == scan_run_id,
                ScanStage.stage == "discover",
            )
        )
        stage.status = "running"
        session.commit()

        # Suspend owner while scan was running
        suspend_user(session, str(owner_id), "Suspended mid-flight")

    # Worker encounters unexpected crash
    worker = ASMWorker(engine=db_engine)
    worker._handle_unexpected_worker_exception(
        scan_run_id=scan_run_id,
        claim_token=claim_token,
        error_msg="Unexpected worker crash",
        attempts=1,
        max_attempts=3,
    )

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        # Invariant: run MUST be cancelled, not queued!
        assert run_record.status == "cancelled"
        assert run_record.error == "Scanning is paused for this organization."
        assert run_record.claim_token is None

        # Running stage marked failed, pending stages marked skipped
        stages = {st.stage: st.status for st in session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()}
        assert stages["discover"] == "failed"
        assert stages["probe"] == "skipped"


def test_unexpected_worker_exception_normal_requeues_with_backoff(clean_db, db_engine):
    """When organization is not suspended, unexpected worker exception cleanly requeues the run."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "NormalRetry Org")
        domain = Domain(
            org_id=org_id,
            name="normal-retry.example.com",
            verification_status="verified",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    claim_token = uuid.uuid4()
    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        run_record.status = "running"
        run_record.claim_token = claim_token
        run_record.claimed_by = "test-worker"
        run_record.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
        session.commit()

    worker = ASMWorker(engine=db_engine)
    worker._handle_unexpected_worker_exception(
        scan_run_id=scan_run_id,
        claim_token=claim_token,
        error_msg="Temporary network glitch",
        attempts=1,
        max_attempts=3,
    )

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "queued"
        assert run_record.claim_token is None
        assert run_record.next_attempt_at is not None
        assert "Unexpected worker error" in (run_record.error or "")


# ==============================================================================
# 5. Pre-Alert Verification Check & Normal End-to-End Scan
# ==============================================================================


def test_expired_domain_suppresses_alert_digest_persisted(clean_db, db_engine):
    """If verification expires before alert digest, no alert notifications are created."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "AlertSuppression Org")
        domain = Domain(
            org_id=org_id,
            name="alert-suppress.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) + timedelta(hours=1),
            alerts_enabled=True,
            alert_emails=["security@alert-suppress.example.com"],
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id
        enqueue_scan(session, domain.id, trigger="manual")
        session.commit()

    class AlertExpiringRunner(MockStageRunner):
        def run_score(self, domain: str, **kwargs: Any) -> dict[str, Any]:
            res = super().run_score(domain, **kwargs)
            # Expire the domain during the final stage before alerts are evaluated
            with Session(db_engine) as s:
                d = s.get(Domain, domain_id)
                d.verification_expires_at = datetime.now(UTC) - timedelta(seconds=1)
                s.commit()
            return res

    worker = ASMWorker(engine=db_engine, runner=AlertExpiringRunner())
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        alerts = session.scalars(
            select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        ).all()
        # Zero alert notifications persisted because verification expired
        assert len(alerts) == 0


def test_normal_authorized_scan_completes_succeeded_in_database(clean_db, db_engine):
    """A verified domain executes all stages cleanly and persists results in PostgreSQL."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "Healthy Org")
        domain = Domain(
            org_id=org_id,
            name="healthy.example.com",
            verification_status="verified",
            verification_method="dns_txt",
            verification_expires_at=None,
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    mock_runner = MockStageRunner()
    worker = ASMWorker(engine=db_engine, runner=mock_runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "succeeded"
        assert run_record.error is None
        assert run_record.finished_at is not None

        stages = session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()
        assert len(stages) == 5
        assert all(st.status == "succeeded" for st in stages)

        results = session.scalars(
            select(ScanResult).where(ScanResult.scan_run_id == scan_run_id)
        ).all()
        assert len(results) == 5
        assert mock_runner.invoked_stages == ["discover", "probe", "portscan", "inspect", "score"]


# ==============================================================================
# 6. Cross-Session Authorization Refresh & Active Owner Controls
# ==============================================================================


def test_revocation_between_stages_stops_pipeline_across_sessions(clean_db, db_engine):
    """Operator revocation committed in a separate DB session blocks the next stage."""
    with Session(db_engine) as session:
        org_id, _ = _create_org_with_owner(session, "RevokeCrossSession Org")
        domain = Domain(
            org_id=org_id,
            name="revoke-cross-session.example.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    class RevokingStageRunner(MockStageRunner):
        def run_discover(self, domain_name: str) -> dict[str, Any]:
            res = super().run_discover(domain_name)
            # Operator revokes verification in a separate session
            with Session(db_engine) as separate_session:
                revoke_verification(
                    separate_session, domain_id, reason="Ownership dispute"
                )
                separate_session.commit()
            return res

    runner = RevokingStageRunner()
    worker = ASMWorker(engine=db_engine, runner=runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "failed"
        assert "Domain verification lapsed/revoked" in (run_record.error or "")

        stages = {st.stage: st.status for st in session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()}
        assert stages["discover"] == "succeeded"
        assert stages["probe"] == "skipped"
        assert stages["portscan"] == "skipped"
        assert stages["inspect"] == "skipped"
        assert stages["score"] == "skipped"
        assert runner.invoked_stages == ["discover"]


def test_owner_suspension_between_stages_stops_pipeline_across_sessions(clean_db, db_engine):
    """Suspending sole owner in a separate DB session blocks next stage and skips remaining."""
    with Session(db_engine) as session:
        org_id, owner_id = _create_org_with_owner(session, "SuspendCrossSession Org")
        domain = Domain(
            org_id=org_id,
            name="suspend-cross-session.example.com",
            verification_status="verified",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    class SuspendingStageRunner(MockStageRunner):
        def run_discover(self, domain_name: str) -> dict[str, Any]:
            res = super().run_discover(domain_name)
            # Operator suspends owner in a separate session
            with Session(db_engine) as separate_session:
                suspend_user(
                    separate_session, str(owner_id), reason="Terms violation"
                )
                separate_session.commit()
            return res

    runner = SuspendingStageRunner()
    worker = ASMWorker(engine=db_engine, runner=runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "failed"
        assert "Scanning is paused for org" in (run_record.error or "")

        stages = {st.stage: st.status for st in session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()}
        assert stages["discover"] == "succeeded"
        assert stages["probe"] == "skipped"
        assert stages["portscan"] == "skipped"
        assert stages["inspect"] == "skipped"
        assert stages["score"] == "skipped"
        assert runner.invoked_stages == ["discover"]


def test_active_owner_control_permits_next_stage_when_other_owner_suspended(clean_db, db_engine):
    """When one owner is suspended but another remains active, next stage executes normally."""
    with Session(db_engine) as session:
        org_id, owner1_id = _create_org_with_owner(session, "ControlOwner Org")
        owner2_id = uuid.uuid4()
        owner2 = User(id=owner2_id, email="control2@example.com")
        session.add(owner2)
        session.flush()
        session.add(Membership(org_id=org_id, user_id=owner2_id, role="owner"))

        domain = Domain(
            org_id=org_id,
            name="control-owner.example.com",
            verification_status="verified",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()
        run = enqueue_scan(session, domain.id, trigger="manual")
        scan_run_id = run.id
        session.commit()

    class ControlStageRunner(MockStageRunner):
        def run_discover(self, domain_name: str) -> dict[str, Any]:
            res = super().run_discover(domain_name)
            # Suspend owner 1 only; owner 2 remains active
            with Session(db_engine) as separate_session:
                suspend_user(
                    separate_session, str(owner1_id), reason="First owner suspended"
                )
                separate_session.commit()
            return res

    runner = ControlStageRunner()
    worker = ASMWorker(engine=db_engine, runner=runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        run_record = session.get(ScanRun, scan_run_id)
        assert run_record.status == "succeeded"
        assert run_record.error is None
        stages = {st.stage: st.status for st in session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == scan_run_id)
        ).all()}
        assert all(st == "succeeded" for st in stages.values())
        assert runner.invoked_stages == ["discover", "probe", "portscan", "inspect", "score"]
