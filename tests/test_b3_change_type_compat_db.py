"""v3.6c B-3 compatibility: changes stored before B-3 keep their old type and display
correctly next to the new SECURITY_HEADER_WEAKENED type (API, UI and alert email).
"""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from asm.alerts.digest import build_alert_digest
from asm.alerts.rules import should_trigger_alerts
from asm.db.models import Domain, Membership, Organization, ScanChange, ScanRun

pytestmark = pytest.mark.db

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
HSTS = "Strict-Transport-Security"


@pytest.fixture
def stored_changes(client, db_session: Session):
    """One scan with a pre-B-3 weak-HSTS record (old type) and a post-B-3 one (new type)."""
    org = Organization(name="Compat Org")
    db_session.add(org)
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=TEST_USER_ID, role="owner"))
    domain = Domain(org_id=org.id, name="compat.example.com", verification_status="verified")
    db_session.add(domain)
    db_session.flush()
    baseline = ScanRun(domain_id=domain.id, status="succeeded")
    run = ScanRun(domain_id=domain.id, status="succeeded")
    db_session.add_all([baseline, run])
    db_session.flush()
    now = datetime.now(UTC)
    for change_type, asset in (
        ("SECURITY_HEADER_REMOVED", "old.compat.example.com"),  # stored before v3.6c
        ("SECURITY_HEADER_WEAKENED", "new.compat.example.com"),  # stored after v3.6c
    ):
        db_session.add(
            ScanChange(
                domain_id=domain.id,
                scan_run_id=run.id,
                baseline_scan_run_id=baseline.id,
                change_type=change_type,
                category="exposure",
                severity="LOW",
                asset=asset,
                detail=HSTS,
                evidence="inspect",
                previous_state=None,
                new_state={"finding_id": "HEADER_WEAK_HSTS"},
                observed_at=now,
            )
        )
    db_session.commit()
    return org, domain, run


def test_api_returns_old_and_new_change_types(client, stored_changes):
    org, domain, run = stored_changes
    for path in (
        f"/orgs/{org.id}/scans/{run.id}/changes",
        f"/orgs/{org.id}/domains/{domain.id}/changes",
    ):
        resp = client.get(path)
        assert resp.status_code == 200, resp.text
        types = {c["change_type"] for c in resp.json()}
        assert types == {"SECURITY_HEADER_REMOVED", "SECURITY_HEADER_WEAKENED"}, path

    filtered = client.get(
        f"/orgs/{org.id}/domains/{domain.id}/changes",
        params={"change_type": "SECURITY_HEADER_REMOVED"},
    ).json()
    assert [c["asset"] for c in filtered] == ["old.compat.example.com"]


def test_ui_scan_detail_renders_old_and_new_change_types(client, stored_changes):
    org, _, run = stored_changes
    resp = client.get(f"/ui/orgs/{org.id}/scans/{run.id}")
    assert resp.status_code == 200, resp.text
    assert "SECURITY_HEADER_REMOVED" in resp.text
    assert "SECURITY_HEADER_WEAKENED" in resp.text
    assert "old.compat.example.com" in resp.text and "new.compat.example.com" in resp.text


def test_alert_digest_handles_old_and_new_change_types():
    changes = [
        {
            "change_type": change_type,
            "category": "exposure",
            "severity": "LOW",
            "asset": asset,
            "detail": HSTS,
        }
        for change_type, asset in (
            ("SECURITY_HEADER_REMOVED", "old.compat.example.com"),
            ("SECURITY_HEADER_WEAKENED", "new.compat.example.com"),
        )
    ]
    should_alert, triggering = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["owner@example.com"],
        verified=True,
        alert_min_severity="LOW",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert should_alert is True
    assert {c["change_type"] for c in triggering} == {
        "SECURITY_HEADER_REMOVED",
        "SECURITY_HEADER_WEAKENED",
    }
    subject, body = build_alert_digest("compat.example.com", 1, changes, triggering)
    assert "SECURITY_HEADER_REMOVED" in body
    assert "SECURITY_HEADER_WEAKENED" in body
    assert subject.startswith("[Exposight]")
