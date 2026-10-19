"""Database integration tests for viewer-privacy consistency across API and UI.

Verifies:
1. Viewer cannot access configured alert recipient email addresses or raw delivery errors.
2. DomainRead explicitly distinguishes between unconfigured ([] for admin) and redacted (None),
   while exposing alert_recipient_count to all roles.
3. AlertNotificationRead redacts recipient and last_error to None for viewers, across filters.
4. Protected email addresses and raw delivery errors never appear in viewer response payloads.
5. Server-side serialization does not mutate SQLAlchemy objects or pollute subsequent reads.
6. Web UI renders consistent status and recipient counts without leaking protected fields.
7. Non-members receive HTTP 404 (tenant isolation).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from asm.admin import revoke_verification, verify_domain
from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import AlertNotification, Domain, Membership, Organization, User
from asm.db.session import get_db

pytestmark = pytest.mark.db


def _make_client_for_user(user: User, db_session: Session) -> TestClient:
    """Create a TestClient authenticated as the specified user."""
    def _override_user():
        return user

    def _override_db():
        yield db_session

    app.dependency_overrides[get_current_user] = _override_user
    app.dependency_overrides[get_db] = _override_db
    return TestClient(app)


@pytest.fixture
def privacy_fixture(db_session: Session):
    """Fixture with organization, owner, admin, viewer, outsider, and domains with alerts."""
    owner_user = User(id=uuid.uuid4(), email="owner@privacy-corp.example")
    admin_user = User(id=uuid.uuid4(), email="admin@privacy-corp.example")
    viewer_user = User(id=uuid.uuid4(), email="viewer@privacy-corp.example")
    outsider_user = User(id=uuid.uuid4(), email="outsider@unrelated.example")

    db_session.add_all([owner_user, admin_user, viewer_user, outsider_user])
    db_session.flush()

    org = Organization(name="Privacy Guarded Corp")
    db_session.add(org)
    db_session.flush()

    db_session.add_all([
        Membership(org_id=org.id, user_id=owner_user.id, role="owner"),
        Membership(org_id=org.id, user_id=admin_user.id, role="admin"),
        Membership(org_id=org.id, user_id=viewer_user.id, role="viewer"),
    ])
    db_session.flush()

    secret_email_1 = "sec-incident-responder@privacy-corp.example"
    secret_email_2 = "ciso-confidential@privacy-corp.example"
    secret_email_3 = "ops-pagerduty@privacy-corp.example"

    dom_with_alerts = Domain(
        org_id=org.id,
        name="critical-service.privacy-corp.example",
        verification_status="verified",
        verification_token="tok-crit-priv-1",
        verification_method="dns_txt",
        alerts_enabled=True,
        alert_emails=[secret_email_1, secret_email_2],
        alert_min_severity="HIGH",
    )
    dom_no_alerts = Domain(
        org_id=org.id,
        name="public-site.privacy-corp.example",
        verification_status="verified",
        verification_token="tok-pub-priv-2",
        verification_method="dns_txt",
        alerts_enabled=False,
        alert_emails=[],
        alert_min_severity="MEDIUM",
    )
    db_session.add_all([dom_with_alerts, dom_no_alerts])
    db_session.flush()

    # Create 6 notifications for dom_with_alerts
    raw_smtp_error = (
        "SMTP 554 Relay access denied for "
        "sec-incident-responder@privacy-corp.example on relay.dmz.local"
    )
    body_crit = (
        "ASM Attack Surface Alert\n"
        "Domain: critical-service.privacy-corp.example\n"
        "Severity: CRITICAL"
    )
    body_high = (
        "ASM Attack Surface Alert\n"
        "Domain: critical-service.privacy-corp.example\n"
        "Severity: HIGH"
    )
    body_med = (
        "ASM Attack Surface Alert\n"
        "Domain: critical-service.privacy-corp.example\n"
        "Severity: MEDIUM"
    )

    notifs = [
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_1,
            subject="[Exposight] CRITICAL: 1 new exposure on critical-service.privacy-corp.example",
            body=body_crit,
            status="sent",
            attempts=1,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC),
            sent_at=datetime.now(UTC),
        ),
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_2,
            subject="[Exposight] CRITICAL: 1 new exposure on critical-service.privacy-corp.example",
            body=body_crit,
            status="sent",
            attempts=1,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC),
            sent_at=datetime.now(UTC),
        ),
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_1,
            subject="[Exposight] HIGH: 2 new exposures on critical-service.privacy-corp.example",
            body=body_high,
            status="pending",
            attempts=0,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC),
        ),
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_3,
            subject="[Exposight] HIGH: 2 new exposures on critical-service.privacy-corp.example",
            body=body_high,
            status="pending",
            attempts=0,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC),
        ),
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_1,
            subject="[Exposight] MEDIUM: 1 new exposure on critical-service.privacy-corp.example",
            body=body_med,
            status="failed",
            attempts=3,
            max_attempts=3,
            last_error=raw_smtp_error,
            next_attempt_at=datetime.now(UTC),
        ),
        AlertNotification(
            domain_id=dom_with_alerts.id,
            recipient=secret_email_2,
            subject="[Exposight] MEDIUM: 1 new exposure on critical-service.privacy-corp.example",
            body=body_med,
            status="failed",
            attempts=3,
            max_attempts=3,
            last_error="SMTP connection timed out connecting to 10.0.4.15:25",
            next_attempt_at=datetime.now(UTC),
        ),
    ]
    db_session.add_all(notifs)
    db_session.commit()

    return {
        "org": org,
        "owner": owner_user,
        "admin": admin_user,
        "viewer": viewer_user,
        "outsider": outsider_user,
        "dom_with_alerts": dom_with_alerts,
        "dom_no_alerts": dom_no_alerts,
        "emails": [secret_email_1, secret_email_2, secret_email_3],
        "raw_error": raw_smtp_error,
        "db_session": db_session,
    }


def test_domains_list_viewer_redaction(privacy_fixture):
    """GET /orgs/{id}/domains redacts alert_emails to None for viewer while preserving count."""
    fix = privacy_fixture
    org_id = fix["org"].id
    db_s = fix["db_session"]

    try:
        # 1. Non-member receives 404
        client_out = _make_client_for_user(fix["outsider"], db_s)
        res_out = client_out.get(f"/orgs/{org_id}/domains")
        assert res_out.status_code == 404

        # 2. Viewer receives domains with alert_emails=None and accurate alert_recipient_count
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_viewer = client_viewer.get(f"/orgs/{org_id}/domains")
        assert res_viewer.status_code == 200
        viewer_domains = res_viewer.json()
        assert len(viewer_domains) == 2

        by_id = {d["id"]: d for d in viewer_domains}
        v_crit = by_id[fix["dom_with_alerts"].id]
        assert v_crit["alert_emails"] is None
        assert v_crit["alert_recipient_count"] == 2
        assert v_crit["alerts_enabled"] is True

        v_pub = by_id[fix["dom_no_alerts"].id]
        assert v_pub["alert_emails"] is None
        assert v_pub["alert_recipient_count"] == 0
        assert v_pub["alerts_enabled"] is False

        # Verify no secret email address appears anywhere in viewer response body
        for secret_email in fix["emails"]:
            assert secret_email not in res_viewer.text

        # 3. Admin receives full email list
        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_admin = client_admin.get(f"/orgs/{org_id}/domains")
        assert res_admin.status_code == 200
        admin_domains = res_admin.json()
        by_id_admin = {d["id"]: d for d in admin_domains}
        a_crit = by_id_admin[fix["dom_with_alerts"].id]
        assert a_crit["alert_emails"] == fix["dom_with_alerts"].alert_emails
        assert a_crit["alert_recipient_count"] == 2

        a_pub = by_id_admin[fix["dom_no_alerts"].id]
        assert a_pub["alert_emails"] == []
        assert a_pub["alert_recipient_count"] == 0

        # 4. Owner receives full email list
        client_owner = _make_client_for_user(fix["owner"], db_s)
        res_owner = client_owner.get(f"/orgs/{org_id}/domains")
        assert res_owner.status_code == 200
        by_id_owner = {d["id"]: d for d in res_owner.json()}
        expected_emails = fix["dom_with_alerts"].alert_emails
        assert by_id_owner[fix["dom_with_alerts"].id]["alert_emails"] == expected_emails
    finally:
        app.dependency_overrides.clear()


def test_domain_detail_viewer_redaction(privacy_fixture):
    """GET /orgs/{id}/domains/{domain_id} redacts alert_emails to None for viewer."""
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    dom_no_alerts_id = fix["dom_no_alerts"].id
    db_s = fix["db_session"]

    try:
        # 1. Non-member gets 404
        client_out = _make_client_for_user(fix["outsider"], db_s)
        res_out = client_out.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_out.status_code == 404

        # 2. Viewer gets None for alert_emails on domain with alerts, count=2
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_viewer = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_viewer.status_code == 200
        data = res_viewer.json()
        assert data["alert_emails"] is None
        assert data["alert_recipient_count"] == 2
        for secret_email in fix["emails"]:
            assert secret_email not in res_viewer.text

        # Viewer on domain with no alerts: alert_emails is None, count=0
        res_no_alerts = client_viewer.get(f"/orgs/{org_id}/domains/{dom_no_alerts_id}")
        assert res_no_alerts.status_code == 200
        data_no_alerts = res_no_alerts.json()
        assert data_no_alerts["alert_emails"] is None
        assert data_no_alerts["alert_recipient_count"] == 0

        # 3. Admin gets full email list
        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_admin = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_admin.status_code == 200
        data_admin = res_admin.json()
        assert data_admin["alert_emails"] == fix["dom_with_alerts"].alert_emails
        assert data_admin["alert_recipient_count"] == 2

        # 4. Owner gets full email list
        client_owner = _make_client_for_user(fix["owner"], db_s)
        res_owner = client_owner.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_owner.status_code == 200
        assert res_owner.json()["alert_emails"] == fix["dom_with_alerts"].alert_emails
    finally:
        app.dependency_overrides.clear()


def test_alert_notifications_history_pagination_and_filtering(privacy_fixture):
    """GET /alert-notifications redacts recipient and last_error across pagination and filters."""
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    db_s = fix["db_session"]

    try:
        # 1. Non-member gets 404
        client_out = _make_client_for_user(fix["outsider"], db_s)
        res_out = client_out.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_out.status_code == 404

        # 2. Viewer gets all notifications with recipient=None, last_error=None
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_viewer = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_viewer.status_code == 200
        notifs = res_viewer.json()
        assert len(notifs) == 6
        for n in notifs:
            assert n["recipient"] is None
            assert n["last_error"] is None
            assert "critical-service.privacy-corp.example" in n["subject"]

        # Assert no secret email or internal error string in viewer response body
        for secret_email in fix["emails"]:
            assert secret_email not in res_viewer.text
        assert "relay.dmz.local" not in res_viewer.text
        assert "10.0.4.15" not in res_viewer.text

        # 3. Pagination with limit and offset maintains redaction
        url_p1 = f"/orgs/{org_id}/domains/{dom_id}/alert-notifications?limit=2&offset=0"
        res_page1 = client_viewer.get(url_p1)
        assert res_page1.status_code == 200
        page1 = res_page1.json()
        assert len(page1) == 2
        for n in page1:
            assert n["recipient"] is None
            assert n["last_error"] is None

        url_p2 = f"/orgs/{org_id}/domains/{dom_id}/alert-notifications?limit=2&offset=2"
        res_page2 = client_viewer.get(url_p2)
        assert res_page2.status_code == 200
        page2 = res_page2.json()
        assert len(page2) == 2
        for n in page2:
            assert n["recipient"] is None
            assert n["last_error"] is None

        # 4. Status filtering maintains redaction
        url_failed = f"/orgs/{org_id}/domains/{dom_id}/alert-notifications?status=failed"
        res_failed = client_viewer.get(url_failed)
        assert res_failed.status_code == 200
        failed_notifs = res_failed.json()
        assert len(failed_notifs) == 2
        for n in failed_notifs:
            assert n["status"] == "failed"
            assert n["recipient"] is None
            assert n["last_error"] is None
        assert "relay.dmz.local" not in res_failed.text

        # 5. Admin sees recipient and last_error on every notification
        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_admin = client_admin.get(url_failed)
        assert res_admin.status_code == 200
        admin_failed = res_admin.json()
        assert len(admin_failed) == 2
        recipients = [n["recipient"] for n in admin_failed]
        assert fix["emails"][0] in recipients
        assert fix["emails"][1] in recipients
        errors = [n["last_error"] for n in admin_failed]
        assert any("relay.dmz.local" in (e or "") for e in errors)
    finally:
        app.dependency_overrides.clear()


def test_viewer_read_does_not_mutate_db_or_pollute_admin(privacy_fixture, db_session: Session):
    """Reading as viewer does NOT write None to DB rows and does not affect admin reads."""
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    db_s = fix["db_session"]

    try:
        client_viewer = _make_client_for_user(fix["viewer"], db_s)

        # Multiple viewer reads across endpoints
        res1 = client_viewer.get(f"/orgs/{org_id}/domains")
        assert res1.status_code == 200
        res2 = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res2.status_code == 200
        res3 = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res3.status_code == 200

        # Direct SQL inspection of database rows: verify alert_emails in DB was NEVER overwritten
        db_emails = db_session.execute(
            text("SELECT alert_emails FROM domains WHERE id = :id"),
            {"id": dom_id},
        ).scalar()
        assert db_emails == fix["dom_with_alerts"].alert_emails

        # Direct SQL inspection of notification recipients in DB
        sql_failed = (
            "SELECT recipient, last_error FROM alert_notifications "
            "WHERE domain_id = :id AND status = 'failed'"
        )
        db_recipients = db_session.execute(text(sql_failed), {"id": dom_id}).fetchall()
        assert len(db_recipients) == 2
        for row in db_recipients:
            assert row[0] is not None
            assert row[0] in fix["emails"]

        # Subsequent admin read immediately gets full data without session pollution
        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_admin_dom = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_admin_dom.status_code == 200
        assert res_admin_dom.json()["alert_emails"] == fix["dom_with_alerts"].alert_emails

        res_admin_notifs = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_admin_notifs.status_code == 200
        for n in res_admin_notifs.json():
            assert n["recipient"] is not None
            assert n["recipient"] in fix["emails"]
    finally:
        app.dependency_overrides.clear()


def test_web_ui_viewer_view_consistency(privacy_fixture):
    """Web UI displays configured recipient count to viewer while hiding addresses and errors."""
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    db_s = fix["db_session"]

    try:
        # 1. Domain detail HTML partial
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_v_detail = client_viewer.get(f"/ui/orgs/{org_id}/domains/{dom_id}")
        assert res_v_detail.status_code == 200
        assert "2 recipients configured" in res_v_detail.text
        # Settings form and email chip list are absent
        assert "alerts-settings-form" not in res_v_detail.text
        for secret_email in fix["emails"]:
            assert secret_email not in res_v_detail.text

        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_a_detail = client_admin.get(f"/ui/orgs/{org_id}/domains/{dom_id}")
        assert res_a_detail.status_code == 200
        assert "2 recipients configured" in res_a_detail.text
        assert "alerts-settings-form" in res_a_detail.text
        assert fix["emails"][0] in res_a_detail.text
        assert fix["emails"][1] in res_a_detail.text

        # 2. Alert notifications HTML partial
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_v_history = client_viewer.get(
            f"/ui/orgs/{org_id}/domains/{dom_id}/alert-notifications"
        )
        assert res_v_history.status_code == 200
        assert "<th>Recipient</th>" not in res_v_history.text
        assert "<th>Last error</th>" not in res_v_history.text
        for secret_email in fix["emails"]:
            assert secret_email not in res_v_history.text
        assert "relay.dmz.local" not in res_v_history.text

        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_a_history = client_admin.get(
            f"/ui/orgs/{org_id}/domains/{dom_id}/alert-notifications"
        )
        assert res_a_history.status_code == 200
        assert "<th>Recipient</th>" in res_a_history.text
        assert "<th>Last error</th>" in res_a_history.text
        assert fix["emails"][0] in res_a_history.text
        assert "relay.dmz.local" in res_a_history.text
    finally:
        app.dependency_overrides.clear()


def test_g5_1_operator_verification_reasons_redacted_for_viewers_and_notifications_db(
    privacy_fixture,
):
    """G5.1: Operator verification reasons are redacted/hidden from viewer roles and notifications.

    1. Operator grants verification with sensitive email/IP in reason.
       - Owner/admin receives full verification_reason in GET /domains/{id} and /verification.
       - Viewer receives verification_reason=None in both endpoints.
    2. Operator revokes verification with sensitive email/IP in reason.
       - Outbox AlertNotification.body has sensitive tokens replaced with [redacted].
       - Viewer receives verification_reason=None and redacted notification body.
       - Admin/owner receives full verification_reason in domain read and retains audit event.
       - Viewer is forbidden (403) from /audit-events.
    """
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    db_s = fix["db_session"]

    try:
        # 1. Operator grants verification with sensitive contact & IP
        grant_reason = "Approved by CISO ciso-private@privacy-corp.example per ticket 10.20.30.40"
        ret = verify_domain(db_s, domain_id=dom_id, reason=grant_reason, expires_in_days=30)
        assert ret == 0

        # Owner/Admin sees full verification_reason
        client_owner = _make_client_for_user(fix["owner"], db_s)
        res_o_dom = client_owner.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_o_dom.status_code == 200
        assert res_o_dom.json()["verification_reason"] == grant_reason

        res_o_ver = client_owner.get(f"/orgs/{org_id}/domains/{dom_id}/verification")
        assert res_o_ver.status_code == 200
        assert res_o_ver.json()["verification_reason"] == grant_reason

        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_a_dom = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_a_dom.status_code == 200
        assert res_a_dom.json()["verification_reason"] == grant_reason

        # Viewer receives verification_reason=None (redacted/hidden)
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_v_dom = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_v_dom.status_code == 200
        assert res_v_dom.json()["verification_reason"] is None
        assert "ciso-private@privacy-corp.example" not in res_v_dom.text
        assert "10.20.30.40" not in res_v_dom.text

        res_v_ver = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/verification")
        assert res_v_ver.status_code == 200
        assert res_v_ver.json()["verification_reason"] is None
        assert "ciso-private@privacy-corp.example" not in res_v_ver.text
        assert "10.20.30.40" not in res_v_ver.text

        # 2. Operator revokes verification with sensitive contact & IP
        revoke_reason = "Revoked by lead sec-ops@privacy-corp.example from gateway 192.168.1.100"
        ret_rev = revoke_verification(db_s, domain_id=dom_id, reason=revoke_reason)
        assert ret_rev == 0

        # Outbox notification body must NOT contain sensitive email/IP
        stmt = (
            select(AlertNotification)
            .where(
                AlertNotification.domain_id == dom_id,
                AlertNotification.subject == "Domain verification lapsed: monitoring paused",
            )
            .order_by(AlertNotification.id.desc())
        )
        notif = db_s.scalars(stmt).first()
        assert notif is not None
        assert "sec-ops@privacy-corp.example" not in notif.body
        assert "192.168.1.100" not in notif.body
        assert "[redacted]" in notif.body

        # Viewer reading notification history sees redacted body and no sensitive text
        res_v_notifs = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_v_notifs.status_code == 200
        for n in res_v_notifs.json():
            assert "sec-ops@privacy-corp.example" not in n["body"]
            assert "192.168.1.100" not in n["body"]

        # Viewer reading domain or verification endpoint still gets verification_reason=None
        res_v_dom2 = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_v_dom2.status_code == 200
        assert res_v_dom2.json()["verification_reason"] is None

        res_v_ver2 = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/verification")
        assert res_v_ver2.status_code == 200
        assert res_v_ver2.json()["verification_reason"] is None

        # Owner/Admin reading domain receives full revoked reason
        client_owner = _make_client_for_user(fix["owner"], db_s)
        res_o_dom2 = client_owner.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_o_dom2.status_code == 200
        assert "sec-ops@privacy-corp.example" in (res_o_dom2.json()["verification_reason"] or "")

        # Audit events are accessible to admin/owner and redact free text
        res_a_audit = client_admin.get(f"/orgs/{org_id}/audit-events?domain_id={dom_id}")
        assert res_a_audit.status_code == 200
        audit_events = res_a_audit.json()
        assert len(audit_events) >= 2
        for ev in audit_events:
            reason_in_meta = ev.get("metadata", {}).get("reason")
            if reason_in_meta:
                assert "ciso-private@privacy-corp.example" not in reason_in_meta
                assert "sec-ops@privacy-corp.example" not in reason_in_meta

        # Viewer cannot access audit events
        client_viewer = _make_client_for_user(fix["viewer"], db_s)
        res_v_audit = client_viewer.get(f"/orgs/{org_id}/audit-events")
        assert res_v_audit.status_code == 403

    finally:
        app.dependency_overrides.clear()


def test_g5_2_viewer_verification_token_redaction_and_ui_db(privacy_fixture):
    """G5.2 Option A: Viewer cannot see verification_token or verification_record_value.

    Verifies:
    1. GET /orgs/{id}/domains/{domain_id} redacts verification_token and
       verification_record_value to None for viewer, while admin/owner receive full values.
    2. GET /orgs/{id}/domains redacts verification_token and verification_record_value to
       None for viewer across domain list.
    3. GET /orgs/{id}/domains/{domain_id}/verification redacts token and record_value to
       None for viewer, while admin/owner receive full values.
    4. GET /ui/orgs/{id}/domains/{domain_id} completely hides the 'DNS proof of control' setup
       box and action buttons for viewer, while rendering them for admin/owner.
    5. GET /orgs/{id}/members remains accessible to viewers (member directory unchanged).
    6. Alert notification bodies redact verification record prefixes/tokens for viewers.
    """
    fix = privacy_fixture
    org_id = fix["org"].id
    dom_id = fix["dom_with_alerts"].id
    db_s = fix["db_session"]
    raw_token = fix["dom_with_alerts"].verification_token
    raw_record_val = fix["dom_with_alerts"].verification_record_value

    try:
        # A. Viewer role checks
        client_viewer = _make_client_for_user(fix["viewer"], db_s)

        # 1. GET /orgs/{id}/domains/{domain_id}
        res_v_dom = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_v_dom.status_code == 200
        v_data = res_v_dom.json()
        assert v_data["verification_token"] is None
        assert v_data["verification_record_value"] is None
        assert raw_token not in res_v_dom.text
        assert raw_record_val not in res_v_dom.text

        # 2. GET /orgs/{id}/domains (list)
        res_v_list = client_viewer.get(f"/orgs/{org_id}/domains")
        assert res_v_list.status_code == 200
        for d in res_v_list.json():
            assert d["verification_token"] is None
            assert d["verification_record_value"] is None
        assert raw_token not in res_v_list.text

        # 3. GET /orgs/{id}/domains/{domain_id}/verification
        res_v_ver = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/verification")
        assert res_v_ver.status_code == 200
        ver_data = res_v_ver.json()
        assert ver_data["token"] is None
        assert ver_data["record_value"] is None
        assert raw_token not in res_v_ver.text
        assert raw_record_val not in res_v_ver.text

        # 4. GET /ui/orgs/{id}/domains/{domain_id} (HTML partial)
        res_v_ui = client_viewer.get(f"/ui/orgs/{org_id}/domains/{dom_id}")
        assert res_v_ui.status_code == 200
        assert "DNS proof of control" not in res_v_ui.text
        assert "btn-check-verification" not in res_v_ui.text
        assert "btn-rotate-token" not in res_v_ui.text
        assert raw_token not in res_v_ui.text
        assert raw_record_val not in res_v_ui.text

        # 5. GET /orgs/{id}/members remains accessible to viewers (member directory unchanged)
        res_v_members = client_viewer.get(f"/orgs/{org_id}/members")
        assert res_v_members.status_code == 200
        members = res_v_members.json()
        assert len(members) == 3
        member_roles = {m["role"] for m in members}
        assert member_roles == {"owner", "admin", "viewer"}

        # 6. Alert notification bodies mask verification token / record value for viewers
        notif = AlertNotification(
            domain_id=dom_id,
            recipient="admin@privacy-corp.example",
            subject="Verification Challenge",
            body=f"Please verify domain with {raw_record_val} or token {raw_token}",
            status="sent",
            attempts=1,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC),
            sent_at=datetime.now(UTC),
        )
        db_s.add(notif)
        db_s.commit()

        res_v_notifs = client_viewer.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_v_notifs.status_code == 200
        v_notif = next(n for n in res_v_notifs.json() if n["subject"] == "Verification Challenge")
        assert raw_record_val not in v_notif["body"]
        assert raw_token not in v_notif["body"]
        assert "[redacted]" in v_notif["body"]

        # B. Admin role checks
        client_admin = _make_client_for_user(fix["admin"], db_s)
        res_a_dom = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_a_dom.status_code == 200
        a_data = res_a_dom.json()
        assert a_data["verification_token"] == raw_token
        assert a_data["verification_record_value"] == raw_record_val

        res_a_ver = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}/verification")
        assert res_a_ver.status_code == 200
        assert res_a_ver.json()["token"] == raw_token
        assert res_a_ver.json()["record_value"] == raw_record_val

        res_a_ui = client_admin.get(f"/ui/orgs/{org_id}/domains/{dom_id}")
        assert res_a_ui.status_code == 200
        assert "DNS proof of control" in res_a_ui.text
        assert "btn-check-verification" in res_a_ui.text
        assert "btn-rotate-token" in res_a_ui.text
        assert raw_record_val in res_a_ui.text

        res_a_notifs = client_admin.get(f"/orgs/{org_id}/domains/{dom_id}/alert-notifications")
        assert res_a_notifs.status_code == 200
        a_notif = next(n for n in res_a_notifs.json() if n["subject"] == "Verification Challenge")
        assert raw_record_val in a_notif["body"]
        assert raw_token in a_notif["body"]

        # C. Owner role checks
        client_owner = _make_client_for_user(fix["owner"], db_s)
        res_o_dom = client_owner.get(f"/orgs/{org_id}/domains/{dom_id}")
        assert res_o_dom.status_code == 200
        o_data = res_o_dom.json()
        assert o_data["verification_token"] == raw_token
        assert o_data["verification_record_value"] == raw_record_val

    finally:
        app.dependency_overrides.clear()


