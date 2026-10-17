"""Regression tests for frontend security and accurate state presentation.

Covers:
1. Expired verification presented as 'Status: expired' rather than 'verified', with
   scan run button disabled and schedule/alert warning blocks enforced.
2. Incomplete or failed scans (failed, cancelled, queued, running) never presented
   as confirmed absence of exposure ('No findings reported' / 'No changes detected').
3. Outbox alert history distinguishes 'Suppressed' notifications from transmission 'Failed',
   and truthfully clarifies SMTP acceptance vs inbox delivery.
4. Tenant isolation across organization switches, beforeSwap late-response guards,
   logout cleanup, and HTMX error handling in app.js.
5. Strict XSS escaping of untrusted domain names, certificates, banners, findings,
   and error messages across all server-rendered HTML fragments.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
    ScanStage,
    User,
)
from asm.worker.worker import ASMWorker


@pytest.mark.db
def test_expired_verification_presentation_and_guards(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Expired domain verification must be presented as expired, not verified."""
    now = datetime.now(UTC)
    # 1. Create domain with status='verified' but expired yesterday
    domain = Domain(
        org_id=test_org.id,
        name="expired-domain.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_token="tok-expired",
        verification_expires_at=now - timedelta(days=1),
        verified_at=now - timedelta(days=30),
        alerts_enabled=False,
    )
    db_session.add(domain)
    db_session.flush()

    assert domain.is_verified is False

    # A. Check domains list partial
    resp_domains = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp_domains.status_code == 200
    assert "Status: expired" in resp_domains.text
    assert "status-badge status-lapsed" in resp_domains.text
    # Must NOT render as verified
    assert "Status: verified" not in resp_domains.text

    # B. Check domain detail partial
    resp_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_detail.status_code == 200
    assert "Status: expired" in resp_detail.text
    assert "status-badge status-lapsed" in resp_detail.text
    assert "Status: verified" not in resp_detail.text
    # Verification warnings must be shown because is_verified is False
    assert (
        "Domain ownership verification required before scheduling automated scans."
        in resp_detail.text
    )
    assert (
        "Domain ownership verification required before enabling alerts."
        in resp_detail.text
    )
    # Scan interval options must be disabled
    assert '<option value="6" disabled>Every 6 hours</option>' in resp_detail.text
    assert '<option value="24" disabled>Every 24 hours</option>' in resp_detail.text

    # C. Check scans list partial
    resp_scans = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_scans.status_code == 200
    # Run scan button must be disabled with explanation
    assert (
        'disabled title="Domain ownership verification required to run scans"'
        in resp_scans.text
    )
    assert (
        "Domain ownership verification required to run scans."
        in resp_scans.text
    )

    # 2. Control: future-expiring verification must render verified and enabled
    domain.verification_expires_at = now + timedelta(days=10)
    db_session.flush()
    assert domain.is_verified is True

    resp_domains_ok = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp_domains_ok.status_code == 200
    assert "Status: verified" in resp_domains_ok.text
    assert "status-badge status-verified" in resp_domains_ok.text

    resp_detail_ok = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_detail_ok.status_code == 200
    assert "Status: verified" in resp_detail_ok.text
    assert (
        "Domain ownership verification required before scheduling automated scans."
        not in resp_detail_ok.text
    )
    assert (
        "Domain ownership verification required before enabling alerts."
        not in resp_detail_ok.text
    )
    assert '<option value="6">Every 6 hours</option>' in resp_detail_ok.text

    resp_scans_ok = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_scans_ok.status_code == 200
    assert (
        'disabled title="Domain ownership verification required to run scans"'
        not in resp_scans_ok.text
    )


@pytest.mark.db
def test_scan_states_do_not_imply_absence_of_exposure(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Queued, running, failed, and cancelled scans must not appear as confirmed clean results."""
    domain = Domain(
        org_id=test_org.id,
        name="scan-accuracy.example.com",
        verification_status="verified",
        verification_token="tok-acc",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Queued scan
    domain_q = Domain(
        org_id=test_org.id,
        name="queued-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-q",
    )
    db_session.add(domain_q)
    db_session.flush()

    scan_queued = ScanRun(domain_id=domain_q.id, status="queued", trigger="manual")
    db_session.add(scan_queued)
    db_session.flush()

    resp_q = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_queued.id}")
    assert resp_q.status_code == 200
    assert (
        "Scan is queued. Findings will be reported once all pipeline stages complete."
        in resp_q.text
    )
    assert "Scan is queued. Changes will be evaluated once the scan completes." in resp_q.text
    assert "No findings reported for this scan run." not in resp_q.text
    assert "No changes detected in this scan." not in resp_q.text

    # 2. Running scan
    domain_r = Domain(
        org_id=test_org.id,
        name="running-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-r",
    )
    db_session.add(domain_r)
    db_session.flush()

    scan_running = ScanRun(
        domain_id=domain_r.id,
        status="running",
        trigger="scheduled",
        started_at=datetime.now(UTC),
    )
    db_session.add(scan_running)
    db_session.flush()

    resp_r = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_running.id}")
    assert resp_r.status_code == 200
    assert (
        "Scan is running. Findings will be reported once all pipeline stages complete."
        in resp_r.text
    )
    assert "Scan is running. Changes will be evaluated once the scan completes." in resp_r.text
    assert "No findings reported for this scan run." not in resp_r.text
    assert "No changes detected in this scan." not in resp_r.text

    # 3. Failed scan
    domain_f = Domain(
        org_id=test_org.id,
        name="failed-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-f",
    )
    db_session.add(domain_f)
    db_session.flush()

    scan_failed = ScanRun(
        domain_id=domain_f.id,
        status="failed",
        trigger="manual",
        error="Probe stage timed out",
    )
    db_session.add(scan_failed)
    db_session.flush()

    resp_f = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_failed.id}")
    assert resp_f.status_code == 200
    assert "Scan failed before completion. No security findings were recorded." in resp_f.text
    assert "Scan failed before completion. Changes could not be evaluated." in resp_f.text
    assert "No findings reported for this scan run." not in resp_f.text
    assert "No changes detected in this scan." not in resp_f.text

    # 4. Cancelled scan
    domain_c = Domain(
        org_id=test_org.id,
        name="cancelled-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-c",
    )
    db_session.add(domain_c)
    db_session.flush()

    scan_cancelled = ScanRun(
        domain_id=domain_c.id,
        status="cancelled",
        trigger="manual",
        error="Scanning paused due to organization owner suspension",
    )
    db_session.add(scan_cancelled)
    db_session.flush()

    resp_c = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_cancelled.id}")
    assert resp_c.status_code == 200
    assert (
        "Scan was cancelled before completion. No security findings were recorded."
        in resp_c.text
    )
    assert "Scan was cancelled before completion. Changes were not evaluated." in resp_c.text
    assert "No findings reported for this scan run." not in resp_c.text
    assert "No changes detected in this scan." not in resp_c.text

    # 5. Succeeded Baseline scan (first scan established baseline)
    domain_b = Domain(
        org_id=test_org.id,
        name="baseline-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-b",
    )
    db_session.add(domain_b)
    db_session.flush()

    scan_baseline = ScanRun(
        domain_id=domain_b.id,
        status="succeeded",
        trigger="manual",
        change_detection={"status": "baseline"},
        started_at=datetime.now(UTC) - timedelta(seconds=10),
        finished_at=datetime.now(UTC),
    )
    db_session.add(scan_baseline)
    db_session.flush()

    resp_b = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_baseline.id}")
    assert resp_b.status_code == 200
    assert (
        "Baseline scan established. Delta changes will be tracked against subsequent scans."
        in resp_b.text
    )
    assert "No findings reported for this scan run." in resp_b.text

    # 6. Succeeded subsequent scan with 0 changes and 0 findings
    domain_clean = Domain(
        org_id=test_org.id,
        name="clean-scan.example.com",
        verification_status="verified",
        verification_token="tok-acc-clean",
    )
    db_session.add(domain_clean)
    db_session.flush()

    scan_clean = ScanRun(
        domain_id=domain_clean.id,
        status="succeeded",
        trigger="manual",
        change_detection={"status": "computed", "counts": {}},
        started_at=datetime.now(UTC) - timedelta(seconds=12),
        finished_at=datetime.now(UTC),
    )
    db_session.add(scan_clean)
    db_session.flush()

    resp_clean = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_clean.id}")
    assert resp_clean.status_code == 200
    assert "No findings reported for this scan run." in resp_clean.text
    assert "No changes detected in this scan." in resp_clean.text


@pytest.mark.db
def test_notification_outbox_truthful_presentation(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Alert history distinguishes Suppressed from Failed and notes SMTP acceptance."""
    domain = Domain(
        org_id=test_org.id,
        name="alerts-truth.example.com",
        verification_status="verified",
        verification_token="tok-at",
        alerts_enabled=True,
        alert_emails=["admin@example.com"],
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Sent notification
    n_sent = AlertNotification(
        domain_id=domain.id,
        recipient="admin@example.com",
        subject="[Exposight Alert] Open port 443",
        body="Port 443 was discovered open.",
        status="sent",
        sent_at=datetime.now(UTC),
        attempts=1,
    )
    # 2. Pending notification
    n_pending = AlertNotification(
        domain_id=domain.id,
        recipient="admin@example.com",
        subject="[Exposight Alert] Certificate expiring",
        body="Certificate expires in 5 days.",
        status="pending",
        attempts=0,
    )
    # 3. Authorization-suppressed notification
    n_suppressed = AlertNotification(
        domain_id=domain.id,
        recipient="admin@example.com",
        subject="[Exposight Alert] Exposure change",
        body="Change notification suppressed.",
        status="failed",
        attempts=1,
        last_error="Delivery suppressed: domain verification is inactive",
    )
    # 4. Transmission failure notification
    n_failed = AlertNotification(
        domain_id=domain.id,
        recipient="admin@example.com",
        subject="[Exposight Alert] Network failed",
        body="Delivery failed.",
        status="failed",
        attempts=3,
        last_error="SMTP connection refused by peer",
    )
    db_session.add_all([n_sent, n_pending, n_suppressed, n_failed])
    db_session.flush()

    # Check Admin rendering
    resp_admin = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications")
    assert resp_admin.status_code == 200
    # Truthful subtitle
    assert (
        "Sent records SMTP acceptance; suppressed messages are retained without dispatch."
        in resp_admin.text
    )
    assert "dispatched for this domain" not in resp_admin.text
    # Status badges
    assert '<span class="status-badge status-verified">Sent</span>' in resp_admin.text
    assert '<span class="status-badge status-pending">Pending</span>' in resp_admin.text
    assert '<span class="status-badge status-skipped">Suppressed</span>' in resp_admin.text
    assert '<span class="status-badge status-failed">Failed</span>' in resp_admin.text
    # Last error shown for admin
    assert "Delivery suppressed: domain verification is inactive" in resp_admin.text
    assert "SMTP connection refused by peer" in resp_admin.text

    # Check Viewer rendering (privacy preservation)
    viewer_user = User(
        id=UUID("00000000-0000-0000-0000-000000000088"),
        email="viewer88@example.com",
    )
    db_session.add(viewer_user)
    db_session.flush()
    db_session.add(Membership(org_id=test_org.id, user_id=viewer_user.id, role="viewer"))
    db_session.flush()

    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_viewer = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications")
        assert resp_viewer.status_code == 200
        # Viewer sees Suppressed badge and Pending badge
        assert '<span class="status-badge status-skipped">Suppressed</span>' in resp_viewer.text
        assert '<span class="status-badge status-verified">Sent</span>' in resp_viewer.text
        # Recipient and last_error columns are redacted
        assert "<th>Recipient</th>" not in resp_viewer.text
        assert "<th>Last error</th>" not in resp_viewer.text
        assert "admin@example.com" not in resp_viewer.text
        assert "SMTP connection refused" not in resp_viewer.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_app_js_security_and_tenant_swap_invariants():
    """Client JS must enforce HTMX security, drop late tenant swaps, and clear DOM on logout."""
    app_js_path = (
        Path(__file__).resolve().parent.parent / "src" / "asm" / "static" / "js" / "app.js"
    )
    content = app_js_path.read_text(encoding="utf-8")

    # 1. Zero innerHTML assignments
    assert "innerHTML" not in content

    # 2. HTMX script evaluation disabled
    assert "window.htmx.config.allowEval = false" in content
    assert "window.htmx.config.allowScriptTags = false" in content

    # 3. htmx:beforeSwap listener guards against tenant confusion
    assert "htmx:beforeSwap" in content
    assert "currentSelectedOrgId" in content
    assert "evt.detail.shouldSwap = false" in content
    # Regex recognizes /ui/orgs/{id}/
    assert r"/^\/ui\/orgs\/(\d+)\//" in content

    # 4. htmx:responseError handles 403, 404, 500
    assert "xhr.status === 404" in content
    assert "xhr.status === 403" in content
    assert "xhr.status >= 500" in content

    # 5. onUserSignedOut clears user email from DOM and resets currentSelectedOrgId
    assert "userDisplay.textContent = ''" in content
    assert "currentSelectedOrgId = null" in content


@pytest.mark.db
def test_untrusted_data_xss_escaping_inert_fixtures(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Inert XSS payloads are escaped across all UI fragments."""
    xss_domain_name = "test-xss<script>alert(1)</script>.example.com"
    domain = Domain(
        org_id=test_org.id,
        name=xss_domain_name,
        verification_status="verified",
        verification_token="tok-xss",
    )
    db_session.add(domain)
    db_session.flush()

    xss_finding = {
        "id": "XSS_FINDING_1",
        "title": "XSS Finding <img src=x onerror=alert('title')>",
        "tier": "HIGH",
        "points": 25,
        "host": "host<script>alert('host')</script>.example.com",
        "port": 443,
        "evidence": "Cert field CN=<b onmouseover=alert('ev')>",
        "why_it_matters": "Risk: <iframe src=javascript:alert('why')>",
    }
    scan = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
        error="Inspect error <script>alert('err')</script>",
    )
    db_session.add(scan)
    db_session.flush()

    db_session.add(
        ScanResult(
            scan_run_id=scan.id,
            stage="score",
            report={
                "domain_score": 75,
                "domain_band": "HIGH",
                "hosts": [{"subdomain": domain.name, "findings": [xss_finding]}],
            },
        )
    )
    db_session.add(
        ScanChange(
            domain_id=domain.id,
            scan_run_id=scan.id,
            baseline_scan_run_id=scan.id,
            category="network",
            change_type="PORT_NEWLY_OPEN",
            asset="port:8080<script>alert('asset')</script>",
            severity="HIGH",
            detail="Opened <b onmouseover=alert('detail')>",
            evidence="Banner <script>alert('ev')</script>",
            observed_at=datetime.now(UTC),
        )
    )
    db_session.add(
        AlertNotification(
            domain_id=domain.id,
            recipient="sec<script>@example.com",
            subject="Alert <script>alert('subject')</script>",
            body="Body <iframe src=javascript:alert('body')>",
            status="sent",
        )
    )
    db_session.flush()

    # 1. Domains list
    resp_domains = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp_domains.status_code == 200
    assert "<script>alert(1)</script>" not in resp_domains.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in resp_domains.text

    # 2. Domain detail
    resp_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_detail.status_code == 200
    assert "<script>alert(1)</script>" not in resp_detail.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in resp_detail.text

    # 3. Scan detail
    resp_scan = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp_scan.status_code == 200
    assert "<img src=x onerror" not in resp_scan.text
    assert "&lt;img src=x onerror" in resp_scan.text
    assert "<b onmouseover" not in resp_scan.text
    assert "&lt;b onmouseover" in resp_scan.text
    assert "<iframe src=" not in resp_scan.text
    assert "&lt;iframe src=" in resp_scan.text
    assert "<script>alert('asset')" not in resp_scan.text
    assert "&lt;script&gt;alert(&#39;asset&#39;)" in resp_scan.text

    # 4. Alert notifications
    resp_alerts = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications")
    assert resp_alerts.status_code == 200
    assert "<script>alert('subject')</script>" not in resp_alerts.text
    assert "&lt;script&gt;alert(&#39;subject&#39;)&lt;/script&gt;" in resp_alerts.text
    assert "<iframe src=" not in resp_alerts.text
    assert "&lt;iframe src=" in resp_alerts.text


@pytest.mark.db
def test_worker_delivery_suppression_api_serialization_and_ui_rendering(
    lifecycle_client: TestClient, db_engine, lifecycle_org: Organization
):
    """Real worker deliver_pending_alerts marks suppressed alerts; API/UI reflect truthful state."""
    session_factory = sessionmaker(bind=db_engine)

    with session_factory() as s:
        domain = Domain(
            org_id=lifecycle_org.id,
            name="worker-suppression-truth.example.com",
            verification_status="verified",
            verification_token="tok-supp-truth",
            alerts_enabled=True,
            alert_emails=["alice@example.com", "bob@example.com"],
        )
        s.add(domain)
        s.commit()
        dom_id = domain.id

        # Notification 1: Alice's notification, suppressed when removed from alert_emails
        n_supp = AlertNotification(
            domain_id=dom_id,
            recipient="alice@example.com",
            subject="[Exposight Alert] Open port 22",
            body="SSH port was detected.",
            status="pending",
            attempts=0,
            max_attempts=3,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        # Notification 2: Bob's notification, Bob remains configured but SMTP fails
        n_smtp_fail = AlertNotification(
            domain_id=dom_id,
            recipient="bob@example.com",
            subject="[Exposight Alert] SQL port 3306",
            body="MySQL port was detected.",
            status="pending",
            attempts=0,
            max_attempts=1,  # immediate failure on attempt 1
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        s.add_all([n_supp, n_smtp_fail])
        s.commit()
        supp_id = n_supp.id
        fail_id = n_smtp_fail.id

        # Modify domain so alice is no longer in alert_emails (authorization revoked)
        dom_obj = s.get(Domain, dom_id)
        dom_obj.alert_emails = ["bob@example.com"]
        s.commit()

    # Run the real ASMWorker deliver_pending_alerts with mocked send_smtp_email
    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch(
        "asm.worker.worker.send_smtp_email",
        side_effect=ConnectionRefusedError("SMTP connection refused by peer"),
    ):
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0

    # Verify DB state directly
    with session_factory() as s:
        row_supp = s.get(AlertNotification, supp_id)
        assert row_supp.status == "failed"
        assert row_supp.attempts == 0  # no send attempted
        assert row_supp.last_error.startswith("Delivery suppressed:")
        assert "Recipient is no longer configured" in row_supp.last_error

        row_fail = s.get(AlertNotification, fail_id)
        assert row_fail.status == "failed"
        assert row_fail.attempts == 1
        assert "connection refused" in row_fail.last_error.lower()
        assert not row_fail.last_error.startswith("Delivery suppressed:")

    # 1. Admin checks JSON API: GET /orgs/{org_id}/domains/{domain_id}/alert-notifications
    resp_api_admin = lifecycle_client.get(
        f"/orgs/{lifecycle_org.id}/domains/{dom_id}/alert-notifications"
    )
    assert resp_api_admin.status_code == 200
    api_items = {item["id"]: item for item in resp_api_admin.json()}

    admin_supp = api_items[supp_id]
    assert admin_supp["status"] == "failed"
    assert admin_supp["is_suppressed"] is True
    assert admin_supp["recipient"] == "alice@example.com"
    assert admin_supp["last_error"].startswith("Delivery suppressed:")

    admin_fail = api_items[fail_id]
    assert admin_fail["status"] == "failed"
    assert admin_fail["is_suppressed"] is False
    assert admin_fail["recipient"] == "bob@example.com"
    assert "connection refused" in admin_fail["last_error"].lower()

    # 2. Admin checks UI: GET /ui/orgs/{org_id}/domains/{domain_id}/alert-notifications
    resp_ui_admin = lifecycle_client.get(
        f"/ui/orgs/{lifecycle_org.id}/domains/{dom_id}/alert-notifications"
    )
    assert resp_ui_admin.status_code == 200
    # Suppressed badge rendered for suppressed notification
    assert '<span class="status-badge status-skipped">Suppressed</span>' in resp_ui_admin.text
    # Failed badge rendered for SMTP failure (ordinary SMTP failure must NOT be labeled suppressed)
    assert '<span class="status-badge status-failed">Failed</span>' in resp_ui_admin.text
    # Admin sees recipient and error text
    assert "alice@example.com" in resp_ui_admin.text
    assert "bob@example.com" in resp_ui_admin.text
    assert "Delivery suppressed:" in resp_ui_admin.text

    # 3. Viewer checks JSON API and UI: privacy must remain intact
    viewer_id = UUID("00000000-0000-0000-0000-000000000077")
    with session_factory() as s:
        viewer = User(
            id=viewer_id,
            email="viewer77@example.com",
        )
        s.add(viewer)
        s.flush()
        s.add(Membership(org_id=lifecycle_org.id, user_id=viewer_id, role="viewer"))
        s.commit()

    def _override_viewer():
        with Session(db_engine) as session:
            return session.get(User, viewer_id)

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_api_viewer = lifecycle_client.get(
            f"/orgs/{lifecycle_org.id}/domains/{dom_id}/alert-notifications"
        )
        assert resp_api_viewer.status_code == 200
        v_items = {item["id"]: item for item in resp_api_viewer.json()}

        # Viewer gets truthful is_suppressed boolean, but recipient and last_error are strictly None
        assert v_items[supp_id]["is_suppressed"] is True
        assert v_items[supp_id]["recipient"] is None
        assert v_items[supp_id]["last_error"] is None

        assert v_items[fail_id]["is_suppressed"] is False
        assert v_items[fail_id]["recipient"] is None
        assert v_items[fail_id]["last_error"] is None

        resp_ui_viewer = lifecycle_client.get(
            f"/ui/orgs/{lifecycle_org.id}/domains/{dom_id}/alert-notifications"
        )
        assert resp_ui_viewer.status_code == 200
        # Badges rendered
        assert '<span class="status-badge status-skipped">Suppressed</span>' in resp_ui_viewer.text
        assert '<span class="status-badge status-failed">Failed</span>' in resp_ui_viewer.text
        # Recipient and last_error columns and values are hidden
        assert "<th>Recipient</th>" not in resp_ui_viewer.text
        assert "<th>Last error</th>" not in resp_ui_viewer.text
        assert "alice@example.com" not in resp_ui_viewer.text
        assert "bob@example.com" not in resp_ui_viewer.text
        assert "Delivery suppressed:" not in resp_ui_viewer.text
        assert "connection refused" not in resp_ui_viewer.text.lower()
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_expired_domain_schedule_and_alert_disabling_available(
    client: TestClient, db_session: Session, test_org: Organization
):
    """When verification expires, schedule and alerts can be turned off, but not enabled."""
    now = datetime.now(UTC)
    domain = Domain(
        org_id=test_org.id,
        name="expired-actions.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_token="tok-exp-act",
        verification_expires_at=now - timedelta(days=2),
        verified_at=now - timedelta(days=32),
        scan_interval_hours=24,
        next_scan_at=now + timedelta(hours=12),
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
    )
    db_session.add(domain)
    db_session.flush()

    assert domain.is_verified is False

    # 1. Attempting to change interval to 6 hours fails 422
    resp_sched_change = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/schedule",
        json={"interval_hours": 6},
    )
    assert resp_sched_change.status_code == 422
    assert "not verified" in resp_sched_change.text

    # 2. Turning schedule OFF (interval_hours=None) succeeds 200
    resp_sched_off = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/schedule",
        json={"interval_hours": None},
    )
    assert resp_sched_off.status_code == 200
    assert resp_sched_off.json()["scan_interval_hours"] is None
    assert resp_sched_off.json()["next_scan_at"] is None

    # 3. Attempting to keep alerts_enabled=True on expired domain fails 422
    resp_alert_enable = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert resp_alert_enable.status_code == 422
    assert "not verified" in resp_alert_enable.text

    # 4. Turning alerts OFF (alerts_enabled=False) succeeds 200
    resp_alert_off = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": False,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert resp_alert_off.status_code == 200
    assert resp_alert_off.json()["alerts_enabled"] is False


@pytest.mark.db
def test_partial_findings_and_changes_on_terminated_scans(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Failed or cancelled scans with findings or changes show partial warnings."""
    domain = Domain(
        org_id=test_org.id,
        name="partial-findings.example.com",
        verification_status="verified",
        verification_token="tok-part",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Failed scan WITH findings and changes
    scan_failed = ScanRun(
        domain_id=domain.id,
        status="failed",
        trigger="manual",
        error="Probe timed out midway",
    )
    db_session.add(scan_failed)
    db_session.flush()

    finding = {
        "finding_type": "open_port",
        "severity": "HIGH",
        "title": "Open Port 22/tcp",
        "why_it_matters": "Remote shell exposure",
        "target": f"{domain.name}:22",
        "subdomain": domain.name,
        "port": 22,
        "impact_score": 15,
        "evidence": "Open SSH",
    }
    db_session.add(
        ScanResult(
            scan_run_id=scan_failed.id,
            stage="score",
            report={
                "domain_score": 85,
                "domain_band": "MEDIUM",
                "hosts": [{"subdomain": domain.name, "findings": [finding]}],
            },
        )
    )
    db_session.add(
        ScanChange(
            domain_id=domain.id,
            scan_run_id=scan_failed.id,
            baseline_scan_run_id=scan_failed.id,
            category="network",
            change_type="PORT_NEWLY_OPEN",
            asset=f"{domain.name}:22",
            severity="HIGH",
            detail="Discovered open SSH",
            evidence="portscan",
            observed_at=datetime.now(UTC),
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_failed.id}")
    assert resp.status_code == 200
    # Must show partial findings warning
    assert "Partial scan findings:" in resp.text
    assert "Displaying 1 finding(s) recorded prior to termination." in resp.text
    assert "Open Port 22/tcp" in resp.text
    assert "No findings reported" not in resp.text
    assert "No security findings were recorded" not in resp.text

    # Must show partial changes warning
    assert "Partial change detection:" in resp.text
    assert "Displaying 1 change(s) recorded prior to termination." in resp.text
    assert "PORT_NEWLY_OPEN" in resp.text
    assert "No changes detected in this scan." not in resp.text

    # 2. Succeeded scan with truncated discovery stage notice
    scan_succ = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(scan_succ)
    db_session.flush()

    db_session.add(
        ScanResult(
            scan_run_id=scan_succ.id,
            stage="discover",
            report={
                "subdomains": ["a.com"],
                "truncated": True,
                "truncation_reason": "hostname_cap_exceeded",
                "counts": {"selected_hosts": 1000, "observed_hosts": 5000},
            },
        )
    )
    db_session.add(
        ScanStage(
            scan_run_id=scan_succ.id,
            stage="discover",
            status="succeeded",
        )
    )
    db_session.flush()

    resp_succ = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_succ.id}")
    assert resp_succ.status_code == 200
    assert (
        "No findings reported for scanned assets. "
        "(Note: asset discovery was truncated; see pipeline stage notices)."
        in resp_succ.text
    )
    assert "Discovery capped at 1000 hostnames (5000 observed)." in resp_succ.text
