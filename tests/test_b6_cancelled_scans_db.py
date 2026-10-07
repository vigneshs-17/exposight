"""v3.6c B-6: scans cancelled by suspension or org deletion are 'cancelled', not 'failed'."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from asm.admin import suspend_user
from asm.db.models import Domain, Membership, Organization, ScanRun, User
from asm.retention import purge_expired
from tests.test_b1_worker_migrations_db import _alembic, scratch_db_url  # noqa: F401

pytestmark = pytest.mark.db

SUSPENSION_REASON = "Scanning is paused for this organization."


def _domain(db: Session, org: Organization, name: str) -> Domain:
    domain = Domain(org_id=org.id, name=name, verification_status="verified")
    db.add(domain)
    db.flush()
    return domain


def test_suspension_cancels_queued_scan_with_neutral_reason(db_engine, clean_db):
    with Session(db_engine) as session:
        owner = User(id=uuid.uuid4(), email="owner@example.com")
        org = Organization(name="Paused Org")
        session.add_all([owner, org])
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        queued = ScanRun(domain_id=_domain(session, org, "paused.example.com").id)
        session.add(queued)
        session.commit()
        owner_id, scan_id = owner.id, queued.id

    with Session(db_engine) as session:
        assert suspend_user(session, str(owner_id), "operator-only reason") == 0

    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "cancelled"
        assert run.error == SUSPENSION_REASON
        assert run.finished_at is not None


def test_cancelled_scan_in_api_and_dashboard(
    client: TestClient, db_session: Session, test_org: Organization
):
    domain = _domain(db_session, test_org, "cancelled-ui.example.com")
    failed = ScanRun(domain_id=domain.id, status="failed", error="Connection reset")
    cancelled = ScanRun(domain_id=domain.id, status="cancelled", error=SUSPENSION_REASON)
    db_session.add_all([failed, cancelled])
    db_session.flush()

    api = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/scans").json()
    by_id = {item["id"]: item for item in api}
    assert by_id[cancelled.id]["status"] == "cancelled"
    assert by_id[cancelled.id]["error"] == SUSPENSION_REASON
    filtered = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/scans?status=cancelled")
    assert [item["id"] for item in filtered.json()] == [cancelled.id]

    listing = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans").text
    assert "status-badge status-cancelled" in listing
    assert "Status: Cancelled" in listing

    detail = client.get(f"/ui/orgs/{test_org.id}/scans/{cancelled.id}").text
    assert "Scan cancelled:" in detail
    assert SUSPENSION_REASON in detail
    assert "Scan failed:" not in detail
    assert "alert-error" not in detail

    failed_detail = client.get(f"/ui/orgs/{test_org.id}/scans/{failed.id}").text
    assert "Scan failed:" in failed_detail


def test_retention_purges_old_cancelled_scans(db_session: Session, test_org: Organization):
    domain = _domain(db_session, test_org, "cancelled-purge.example.com")
    old = datetime.now(UTC) - timedelta(days=200)
    run = ScanRun(domain_id=domain.id, status="cancelled", created_at=old)
    db_session.add(run)
    db_session.flush()
    run_id = run.id

    counts = purge_expired(db_session, dry_run=False)
    assert counts["scans"] == 1
    assert db_session.scalar(select(ScanRun.id).where(ScanRun.id == run_id)) is None


def test_migration_0014_rewrites_old_cancelled_rows_and_downgrades_exactly(scratch_db_url):  # noqa: F811
    assert _alembic(scratch_db_url, "upgrade", "0013_user_suspension").returncode == 0
    engine = sa.create_engine(scratch_db_url)
    old_rows = [
        ("failed", "Cancelled: every owner of this organization is suspended"),
        ("failed", "Cancelled: organization deleted"),
        ("failed", "Connection reset"),
    ]
    with engine.begin() as conn:
        org_id = conn.execute(
            text("INSERT INTO organizations (name, created_at) VALUES ('O', now()) RETURNING id")
        ).scalar()
        domain_id = conn.execute(
            text(
                "INSERT INTO domains (org_id, name, verification_status, verification_token, "
                "verification_method, consecutive_misses, alerts_enabled, alert_emails, "
                "alert_min_severity, created_at) VALUES (:o, 'm.example.com', 'verified', "
                "'tok', 'dns_txt', 0, false, '[]', 'MEDIUM', now()) RETURNING id"
            ),
            {"o": org_id},
        ).scalar()
        for status, error in old_rows:
            conn.execute(
                text(
                    "INSERT INTO scan_runs (domain_id, status, trigger, created_at, error, "
                    "attempts, max_attempts) VALUES (:d, :s, 'manual', now(), :e, 0, 3)"
                ),
                {"d": domain_id, "s": status, "e": error},
            )

    def rows():
        with engine.connect() as conn:
            return conn.execute(text("SELECT status, error FROM scan_runs ORDER BY id")).all()

    try:
        assert _alembic(scratch_db_url, "upgrade", "head").returncode == 0
        assert rows() == [
            ("cancelled", "Scanning is paused for this organization."),
            ("cancelled", "The organization was deleted."),
            ("failed", "Connection reset"),
        ]
        assert _alembic(scratch_db_url, "downgrade", "0013_user_suspension").returncode == 0
        assert rows() == old_rows
    finally:
        engine.dispose()
