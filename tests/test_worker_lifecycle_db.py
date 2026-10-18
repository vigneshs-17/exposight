"""Tests for G4 worker and owner lifecycle:
G4.1 verification loss during worker exceptions cancels run instead of requeueing
G4.2 stranded queued scans cancelled on verification loss to prevent active scan blockage
G4.3 last-active-owner guards disallow demotion/removal/deletion with suspended co-owners
G4.4 inventory SELECT errors propagate and fail the scan rather than swallowing into empty inventory
G4 finalization after authorization loss keeps evidence but blocks persistence/notifications
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from asm.admin import revoke_verification, suspend_user
from asm.api.deps import get_current_user, get_db
from asm.api.main import app
from asm.db.models import (
    AlertNotification,
    Domain,
    DomainSubdomain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
    User,
)
from asm.db.scans import enqueue_scan
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


def _setup_org_and_domain(
    session: Session, domain_name: str = "lifecycle.example.com", verified: bool = True
) -> tuple[int, int, uuid.UUID]:
    user_id = uuid.uuid4()
    u = User(id=user_id, email=f"user-{user_id.hex[:8]}@example.com")
    org = Organization(name=f"Org-{user_id.hex[:8]}")
    session.add_all([u, org])
    session.flush()

    session.add(Membership(org_id=org.id, user_id=user_id, role="owner"))
    domain = Domain(
        org_id=org.id,
        name=domain_name,
        verification_status="verified" if verified else "pending",
        verification_method="dns_txt" if verified else None,
        verified_at=datetime.now(UTC) if verified else None,
        alerts_enabled=True,
        alert_emails=["alerts@example.com"],
    )
    session.add(domain)
    session.commit()
    return org.id, domain.id, user_id


def test_g4_1_verification_loss_during_exception_cancels_run_instead_of_requeueing(
    clean_db, db_engine
):
    """G4.1: If verification is lost while a scan is running and an unexpected error occurs,

    the run must be cancelled/failed permanently rather than requeued to 'queued' where
    it cannot be claimed and blocks active-domain uniqueness.
    """
    with Session(db_engine) as session:
        org_id, domain_id, _ = _setup_org_and_domain(session, "g4-1.example.com")
        run = enqueue_scan(session, domain_id, trigger="manual")
        run_id = run.id
        session.commit()

    worker = ASMWorker(db_engine)
    claimed = worker.claim_next_job()
    assert claimed is not None
    claimed_run_id, _, claim_token, attempts, max_attempts = claimed
    assert claimed_run_id == run_id

    # Mid-run: verification expires/revoked
    with Session(db_engine) as session:
        dom = session.get(Domain, domain_id)
        dom.verification_status = "pending"
        dom.verified_at = None
        session.commit()
        assert dom.is_verified is False

    # Worker encounters unexpected error
    worker._handle_unexpected_worker_exception(
        scan_run_id=run_id,
        claim_token=claim_token,
        error_msg="Transient network exception",
        attempts=attempts,
        max_attempts=max_attempts,
    )

    with Session(db_engine) as session:
        run_after = session.get(ScanRun, run_id)
        # Must NOT be 'queued'
        assert run_after.status in ("cancelled", "failed")
        assert "verification" in (run_after.error or "").lower()

    # Worker queue must remain clear
    assert worker.claim_next_job() is None


def test_g4_2_stranded_queued_scans_cancelled_on_revocation_and_unblocks_unique_scan(
    clean_db, db_engine
):
    """G4.2: Revoking or losing domain verification must cancel any queued scan runs

    for that domain so they do not strand the domain and violate uq_scan_runs_active_domain
    when re-verified.
    """
    with Session(db_engine) as session:
        org_id, domain_id, _ = _setup_org_and_domain(session, "g4-2.example.com")
        run = enqueue_scan(session, domain_id, trigger="manual")
        run_id = run.id
        session.commit()

    # Operator revokes verification while scan is in 'queued' status
    with Session(db_engine) as session:
        exit_code = revoke_verification(session, domain_id, reason="Compromised domain")
        assert exit_code == 0

    # The queued scan must have been cancelled
    with Session(db_engine) as session:
        run_after = session.get(ScanRun, run_id)
        assert run_after.status == "cancelled"

        # Now re-verify the domain
        dom = session.get(Domain, domain_id)
        dom.verification_status = "verified"
        dom.verified_at = datetime.now(UTC)
        session.commit()

        # Enqueueing a new scan must SUCCEED without IntegrityError on uq_scan_runs_active_domain
        new_run = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        assert new_run.id != run_id
        assert new_run.status == "queued"


def test_g4_3_last_active_owner_guards_disallow_demotion_removal_and_deletion(
    clean_db, db_engine
):
    """G4.3: Demoting or removing an owner, or deleting an account, must check ACTIVE

    (non-suspended) owners. Having a suspended co-owner must NOT allow the sole active
    owner to demote/remove themselves or delete their account.
    """
    owner_active_id = uuid.uuid4()
    owner_suspended_id = uuid.uuid4()

    with Session(db_engine) as session:
        u_active = User(id=owner_active_id, email="active-owner@example.com")
        u_susp = User(id=owner_suspended_id, email="suspended-owner@example.com")
        org = Organization(name="G4-3 Org")
        session.add_all([u_active, u_susp, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=owner_active_id, role="owner"))
        session.add(Membership(org_id=org.id, user_id=owner_suspended_id, role="owner"))
        session.commit()

        # Suspend owner 2
        suspend_user(session, user_id=str(owner_suspended_id), reason="Security breach")
        org_id = org.id

    def _override_db():
        with Session(db_engine) as s:
            yield s

    def _override_active_user():
        with Session(db_engine) as s:
            return s.get(User, owner_active_id)

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_active_user

    try:
        with TestClient(app) as client:
            # 1. Demotion attempt by the sole active owner
            resp_patch = client.patch(
                f"/orgs/{org_id}/members/{owner_active_id}",
                json={"role": "viewer"},
            )
            assert resp_patch.status_code == 422
            assert "last owner" in resp_patch.json()["detail"].lower()

            # 2. Removal attempt by the sole active owner
            resp_del_member = client.delete(
                f"/orgs/{org_id}/members/{owner_active_id}",
            )
            assert resp_del_member.status_code == 422
            assert "last owner" in resp_del_member.json()["detail"].lower()

            # 3. Account deletion attempt by the sole active owner
            resp_del_acct = client.delete("/me")
            assert resp_del_acct.status_code == 409
            assert "only owner" in resp_del_acct.json()["detail"]["message"].lower()

    finally:
        app.dependency_overrides.clear()


def test_g4_4_inventory_select_error_fails_scan_without_fabricating_absence(
    clean_db, db_engine
):
    """G4.4: A database SELECT error during inventory retrieval must fail the scan

    attempt instead of being caught and swallowed into inventory = {}, which would
    fabricate absent subdomains or corrupt inventory state.
    """
    with Session(db_engine) as session:
        org_id, domain_id, _ = _setup_org_and_domain(session, "g4-4.example.com")
        run0 = enqueue_scan(session, domain_id, trigger="manual")
        run0.status = "succeeded"
        session.flush()

        res0 = ScanResult(
            scan_run_id=run0.id,
            stage="discover",
            report={"subdomains": ["api.g4-4.example.com"], "sources": {}},
        )
        session.add(res0)
        session.flush()

        run = enqueue_scan(session, domain_id, trigger="manual")
        run_id = run.id

        # Existing active subdomain
        sub = DomainSubdomain(
            domain_id=domain_id,
            subdomain="api.g4-4.example.com",
            status="active",
            consecutive_qualifying_absences=0,
            first_seen_scan_run_id=run0.id,
            last_seen_scan_run_id=run0.id,
        )
        session.add(sub)
        session.commit()

    worker = ASMWorker(db_engine)
    reports = {
        "discover": {
            "subdomains": ["api.g4-4.example.com"],
            "sources": {"api.g4-4.example.com": ["crtsh"]},
        }
    }

    # Simulate database error on Session.execute when querying domain_subdomains
    real_execute = Session.execute

    def mock_execute(self, statement, *args, **kwargs):
        stmt_str = str(statement)
        if "FROM domain_subdomains" in stmt_str and "SELECT" in stmt_str:
            raise OperationalError(
                "SELECT failed", params=None, orig=Exception("DB connection error")
            )
        return real_execute(self, statement, *args, **kwargs)

    with patch.object(Session, "execute", new=mock_execute):
        with pytest.raises(Exception) as exc_info:
            with Session(db_engine) as session:
                worker._perform_change_detection(run_id, domain_id, reports, session=session)

        # Must raise the OperationalError, NOT swallow it and return summary
        err_msg = str(exc_info.value)
        assert "DB connection error" in err_msg or "SELECT failed" in err_msg


def test_g4_finalization_after_authorization_loss_keeps_evidence_and_blocks_notifications(
    clean_db, db_engine
):
    """G4 finalization: If domain verification is lost right before _mark_run_final,

    already-collected evidence in scan_results is preserved, but the run is marked
    failed/cancelled, and no inventory updates or alert notifications are published.
    """
    with Session(db_engine) as session:
        org_id, domain_id, _ = _setup_org_and_domain(session, "g4-final.example.com")
        run = enqueue_scan(session, domain_id, trigger="manual")
        run_id = run.id
        session.commit()

    worker = ASMWorker(db_engine)
    claimed = worker.claim_next_job()
    assert claimed is not None
    claimed_run_id, _, claim_token, attempts, max_attempts = claimed

    # Pre-populate stage results (already-collected evidence)
    with Session(db_engine) as session:
        res1 = ScanResult(
            scan_run_id=run_id,
            stage="discover",
            report={"subdomains": ["api.g4-final.example.com"], "sources": {}},
        )
        res2 = ScanResult(
            scan_run_id=run_id,
            stage="probe",
            report={"endpoints": []},
        )
        session.add_all([res1, res2])
        session.commit()

    # Now revoke verification before finalization
    with Session(db_engine) as session:
        dom = session.get(Domain, domain_id)
        dom.verification_status = "pending"
        dom.verified_at = None
        session.commit()

    reports = {
        "discover": {"subdomains": ["api.g4-final.example.com"], "sources": {}},
        "probe": {"endpoints": []},
    }

    # Call _mark_run_final as worker would at pipeline end
    worker._mark_run_final(
        scan_run_id=run_id,
        claim_token=claim_token,
        status="succeeded",
        error_msg=None,
        domain_id=domain_id,
        reports=reports,
    )

    with Session(db_engine) as session:
        run_after = session.get(ScanRun, run_id)
        # 1. Run must NOT be succeeded!
        assert run_after.status in ("failed", "cancelled")
        assert "verification" in (run_after.error or "").lower()

        # 2. Already collected stage results are KEPT
        saved_results = session.query(ScanResult).filter_by(scan_run_id=run_id).all()
        assert len(saved_results) == 2
        assert {r.stage for r in saved_results} == {"discover", "probe"}

        # 3. No inventory transitions committed
        inventory_rows = session.query(DomainSubdomain).filter_by(domain_id=domain_id).all()
        assert len(inventory_rows) == 0

        # 4. No scan changes committed
        changes = session.query(ScanChange).filter_by(scan_run_id=run_id).all()
        assert len(changes) == 0

        # 5. No alert notifications queued
        alerts = session.query(AlertNotification).all()
        assert len(alerts) == 0
