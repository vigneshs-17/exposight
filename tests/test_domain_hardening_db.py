"""v3.6b A3: alert-recipient audit metadata, duplicate-domain race -> 409, move_domain resets."""

import json
import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from asm.admin import move_domain
from asm.audit import recipients_changed
from asm.db.models import AuditEvent, Domain, Membership, Organization, ScanRun

pytestmark = pytest.mark.db

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def admin_org(client, db_session: Session) -> Organization:
    """An org where the conftest client user (TEST_USER_ID) is admin."""
    org = Organization(name="Hardening Org")
    db_session.add(org)
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=TEST_USER_ID, role="admin"))
    # Commit (releases the test savepoint; the outer test transaction still rolls back)
    # so a route-level db.rollback() cannot discard this setup.
    db_session.commit()
    return org


def test_recipients_changed_ignores_case_and_order():
    assert recipients_changed(["A@x.com", "b@x.com"], ["b@x.com", "a@X.com"]) is False
    assert recipients_changed(["a@x.com"], ["a@x.com", "b@x.com"]) is True
    assert recipients_changed(["a@x.com"], ["c@x.com"]) is True
    assert recipients_changed([], []) is False


def test_alerts_audit_records_recipient_change_without_addresses(
    client, db_session: Session, admin_org: Organization
):
    domain = Domain(
        org_id=admin_org.id,
        name="alerts-audit.example.com",
        verification_status="verified",
        alerts_enabled=True,
        alert_emails=["old@example.com"],
    )
    db_session.add(domain)
    db_session.flush()

    resp = client.put(
        f"/orgs/{admin_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["attacker@evil.example", "old@example.com"],
            "alert_min_severity": "MEDIUM",
        },
    )
    assert resp.status_code == 200, resp.text

    event = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "domain.alerts_changed",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert event is not None
    assert event.metadata_["old_recipient_count"] == 1
    assert event.metadata_["new_recipient_count"] == 2
    assert event.metadata_["recipients_changed"] is True
    assert "@" not in json.dumps(event.metadata_)


def test_alerts_audit_unchanged_recipients_flag_false(
    client, db_session: Session, admin_org: Organization
):
    domain = Domain(
        org_id=admin_org.id,
        name="alerts-same.example.com",
        verification_status="verified",
        alerts_enabled=True,
        alert_emails=["same@example.com"],
    )
    db_session.add(domain)
    db_session.flush()

    resp = client.put(
        f"/orgs/{admin_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["same@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert resp.status_code == 200, resp.text
    event = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "domain.alerts_changed",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert event.metadata_["recipients_changed"] is False


def test_duplicate_domain_race_returns_409_not_500(
    client, db_session: Session, admin_org: Organization, monkeypatch
):
    """Simulate a concurrent insert: the existence pre-check misses, the unique constraint hits."""
    # The "other request" has already committed its row.
    db_session.add(Domain(org_id=admin_org.id, name="race.example.com"))
    db_session.commit()

    real_scalar = db_session.scalar
    calls = {"n": 0}

    def scalar_missing_first_precheck(statement, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # the other request's row was not visible yet
        return real_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(db_session, "scalar", scalar_missing_first_precheck)

    resp = client.post(f"/orgs/{admin_org.id}/domains", json={"name": "race.example.com"})
    monkeypatch.undo()

    assert resp.status_code == 409, resp.text
    assert "already exists" in resp.json()["detail"]
    count = db_session.scalar(
        select(func.count(Domain.id)).where(
            Domain.org_id == admin_org.id, Domain.name == "race.example.com"
        )
    )
    assert count == 1


def _quarantined_configured_domain(db_session: Session) -> tuple[Domain, Organization]:
    quarantine = Organization(name="Legacy Quarantine", system_kind="legacy_quarantine")
    target = Organization(name="New Owner Org")
    db_session.add_all([quarantine, target])
    db_session.flush()
    domain = Domain(
        org_id=quarantine.id,
        name=f"moved-{uuid.uuid4().hex[:8]}.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_token="old-token",
        verification_reason="granted for old org",
        consecutive_misses=1,
        alerts_enabled=True,
        alert_emails=["old-owner@example.com"],
        scan_interval_hours=24,
    )
    db_session.add(domain)
    db_session.commit()
    return domain, target


def test_move_domain_resets_verification_alerts_and_schedule(db_session: Session):
    domain, target = _quarantined_configured_domain(db_session)

    assert move_domain(db_session, domain.id, target.id) == 0
    db_session.refresh(domain)

    assert domain.org_id == target.id
    assert domain.verification_status == "pending"
    assert domain.verification_method == "dns_txt"
    assert domain.verification_token != "old-token"
    assert domain.verified_at is None
    assert domain.verification_reason is None
    assert domain.verification_expires_at is None
    assert domain.consecutive_misses == 0
    assert domain.alerts_enabled is False
    assert domain.alert_emails == []
    assert domain.scan_interval_hours is None
    assert domain.next_scan_at is None

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "domain.moved", AuditEvent.target_id == str(domain.id)
        )
    ).all()
    assert len(events) == 2
    for event in events:
        assert event.metadata_["verification_reset"] is True
        assert event.metadata_["alerts_reset"] is True
        assert event.metadata_["schedule_reset"] is True


@pytest.mark.parametrize("scan_status", ["queued", "running"])
def test_move_domain_refuses_while_scan_active(db_session: Session, scan_status: str):
    domain, target = _quarantined_configured_domain(db_session)
    original_org = domain.org_id
    db_session.add(ScanRun(domain_id=domain.id, status=scan_status))
    db_session.commit()

    assert move_domain(db_session, domain.id, target.id) == 1
    db_session.refresh(domain)
    assert domain.org_id == original_org
    assert domain.verification_status == "verified"


def test_move_domain_allowed_after_scan_finished(db_session: Session):
    domain, target = _quarantined_configured_domain(db_session)
    db_session.add(ScanRun(domain_id=domain.id, status="succeeded"))
    db_session.commit()

    assert move_domain(db_session, domain.id, target.id) == 0
