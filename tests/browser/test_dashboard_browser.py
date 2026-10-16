"""Playwright browser tests for Phase v3.4d.

Tests cover interactions and DOM states requiring a real browser environment:
1. Sign-in and domain inventory rendering with zero CSP violations.
2. Viewer RBAC privacy: write forms absent, recipient counts only, no emails anywhere.
3. Schedule settings on unverified domains (Decision A).
4. Alert recipient email chips (add/remove, duplicate rejection, 5-chip cap).
5. Alerts save settings flow on unverified domain (Decision A).
6. Scan detail polling lifecycle (every 3s auto-refresh ending on completion).
7. 401 refresh-and-retry preserving a single #scan-detail-container.
8. Audit log action/domain filters and keyset pagination.
9. Production app 401 rejection for unverified/synthetic tokens.
10. Live DNS verification "Check now" result persistence across navigation/idle.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch
from uuid import UUID

import pytest
from playwright.sync_api import Page, Route, expect
from sqlalchemy.orm import Session, sessionmaker

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.audit import record_event
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanRun,
    ScanStage,
    User,
)
from asm.verification import VerificationOutcome
from tests.browser.helpers import make_fake_jwt, sign_in

pytestmark = pytest.mark.browser


def test_browser_signin_and_domain_inventory(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Signs in as owner; verifies #app-shell visible, domains rendered, 0 CSP violations."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000001"), email="owner@example.com")
        org = Organization(name="Acme Corp")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="acme.example.com",
            verification_status="verified",
        )
        session.add_all([membership, domain])
        session.commit()

    sign_in(page, "owner@example.com", live_server)

    expect(page.locator("#app-shell")).to_be_visible()
    expect(page.locator("#auth-section")).to_be_hidden()
    expect(page.locator("#user-email-display")).to_have_text("owner@example.com")
    expect(page.locator("#main-content-area")).to_contain_text("Domains for Acme Corp")
    expect(page.locator("#main-content-area")).to_contain_text("acme.example.com")
    expect(page.locator("#main-content-area")).to_contain_text("Status: verified")


def test_browser_viewer_rbac_privacy(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Viewer sees recipient count, no write forms, no emails in history table."""
    secret_email = "secret-security@acme.example.com"
    with browser_session_factory() as session:
        viewer = User(id=UUID("00000000-0000-0000-0000-000000000002"), email="viewer@example.com")
        org = Organization(name="Viewer Org")
        session.add_all([viewer, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=viewer.id, role="viewer")
        domain = Domain(
            org_id=org.id,
            name="viewer.example.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=[secret_email],
            alert_min_severity="HIGH",
        )
        session.add_all([membership, domain])
        session.flush()
        notification = AlertNotification(
            domain_id=domain.id,
            recipient=secret_email,
            subject="Security Alert: New Open Port",
            body="Secret alert body with port info",
            status="failed",
            last_error=f"SMTP recipient error for {secret_email}",
        )
        session.add(notification)
        session.commit()

    sign_in(page, "viewer@example.com", live_server)

    # Navigate to domain detail
    page.locator(".btn-view-domain").click()
    expect(page.locator("#main-content-area")).to_contain_text("viewer.example.com")

    # Viewer sees read-only info
    expect(page.locator("#main-content-area")).to_contain_text("1 recipient configured")
    expect(page.locator("#main-content-area")).to_contain_text("Alerts: enabled")
    # Viewer does NOT see settings forms or buttons
    expect(page.locator("#schedule-settings-form")).to_have_count(0)
    expect(page.locator("#alerts-settings-form")).to_have_count(0)
    expect(page.locator("#btn-check-verification")).to_have_count(0)

    # Navigate to alert history
    page.locator("#btn-view-alert-notifications").click()
    expect(page.locator("#main-content-area")).to_contain_text(
        "Alert history for viewer.example.com"
    )
    expect(page.locator("#main-content-area table.data-table")).to_be_visible()

    # Verify no Recipient / Last error columns
    expect(page.locator("th:has-text('Recipient')")).to_have_count(0)
    expect(page.locator("th:has-text('Last error')")).to_have_count(0)

    # Verify secret_email does not appear anywhere in page DOM
    html = page.content()
    assert secret_email not in html


def test_browser_schedule_unverified_domain(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """On unverified domain, only 'Off' is enabled; notice is visible; saving 'Off' works."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000003"), email="admin3@example.com")
        org = Organization(name="Schedule Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="admin")
        domain = Domain(
            org_id=org.id,
            name="pending.example.com",
            verification_status="pending",
        )
        session.add_all([membership, domain])
        session.commit()

    sign_in(page, "admin3@example.com", live_server)
    page.locator(".btn-view-domain").click()

    expect(page.locator("#schedule-settings-form")).to_be_visible()
    warning_box = page.locator("#schedule-settings-form .alert-warning")
    expect(warning_box).to_contain_text(
        "Domain ownership verification required before scheduling automated scans."
    )

    # Check select options: Off enabled, all other interval options disabled
    select = page.locator("#schedule-interval-select")
    expect(select.locator('option[value=""]')).to_be_enabled()
    expect(select.locator('option[value="6"]')).to_be_disabled()
    expect(select.locator('option[value="12"]')).to_be_disabled()
    expect(select.locator('option[value="24"]')).to_be_disabled()
    expect(select.locator('option[value="168"]')).to_be_disabled()
    expect(select.locator('option[value="720"]')).to_be_disabled()

    # Save schedule with Off
    page.locator("#btn-save-schedule").click()
    expect(page.locator("#schedule-settings-form")).to_be_visible()
    expect(page.locator("#global-error-box")).to_be_hidden()


def test_browser_email_chips_interaction(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Tests chip additions, removal, duplicate case-insensitive rejection, and 5-chip cap."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000004"), email="admin4@example.com")
        org = Organization(name="Chips Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="chips.example.com",
            verification_status="verified",
            alert_emails=[],
        )
        session.add_all([membership, domain])
        session.commit()

    sign_in(page, "admin4@example.com", live_server)
    page.locator(".btn-view-domain").click()

    email_input = page.locator("#input-alert-email")
    add_btn = page.locator("#btn-add-alert-email")
    chips = page.locator("#alert-emails-list .email-chip")
    error_box = page.locator("#global-error-box")

    # Add 1st chip
    email_input.fill("alpha@example.com")
    add_btn.click()
    expect(chips).to_have_count(1)
    expect(chips.first).to_contain_text("alpha@example.com")

    # Reject case-insensitive duplicate
    email_input.fill("ALPHA@example.com")
    add_btn.click()
    expect(chips).to_have_count(1)
    expect(error_box).to_be_visible()
    expect(error_box).to_contain_text("Email address is already in the list.")

    # Remove 1st chip
    chips.first.locator(".btn-remove-email").click()
    expect(chips).to_have_count(0)

    # Add 5 distinct chips
    for i in range(1, 6):
        email_input.fill(f"user{i}@example.com")
        add_btn.click()

    expect(chips).to_have_count(5)

    # Attempt to add 6th chip -> capped
    email_input.fill("user6@example.com")
    add_btn.click()
    expect(chips).to_have_count(5)
    expect(error_box).to_be_visible()
    expect(error_box).to_contain_text("Maximum of 5 alert emails allowed.")


def test_browser_add_recipient_input_is_single_line_on_phone(
    make_page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """C-UI-3: at 390px the add-recipient input keeps a single-line height, button below it."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-0000000000c4"), email="phone@example.com")
        org = Organization(name="Phone Org")
        session.add_all([user, org])
        session.flush()
        session.add_all(
            [
                Membership(org_id=org.id, user_id=user.id, role="owner"),
                Domain(org_id=org.id, name="phone.example.com", verification_status="verified"),
            ]
        )
        session.commit()

    with make_page(viewport={"width": 390, "height": 844}) as page:
        sign_in(page, "phone@example.com", live_server)
        page.locator(".btn-view-domain").click()
        email_input = page.locator("#input-alert-email")
        expect(email_input).to_be_visible()
        box = email_input.bounding_box()
        btn = page.locator("#btn-add-alert-email").bounding_box()
        assert box is not None and btn is not None
        assert box["height"] < 60, f"add-recipient input is {box['height']}px tall at 390px"
        assert btn["y"] >= box["y"] + box["height"], "Add email button is not below the input"


def test_browser_alerts_save_decision_a(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Decision A on unverified domain: enabled=true fails (422), enabled=false succeeds."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000005"), email="admin5@example.com")
        org = Organization(name="Alerts Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="unverified-alerts.example.com",
            verification_status="pending",
            alerts_enabled=False,
        )
        session.add_all([membership, domain])
        session.commit()

    sign_in(page, "admin5@example.com", live_server)
    page.locator(".btn-view-domain").click()

    checkbox = page.locator("#alerts-enabled-checkbox")
    save_btn = page.locator("#btn-save-alerts")
    error_box = page.locator("#global-error-box")

    # Add 1 email chip so Pydantic schema validation passes when alerts_enabled=True
    page.locator("#input-alert-email").fill("alerts@example.com")
    page.locator("#btn-add-alert-email").click()

    # 1. Try saving with alerts checked on unverified domain -> expect 422 error
    checkbox.check()
    save_btn.click()
    expect(error_box).to_be_visible()
    expect(error_box).to_contain_text("Domain 'unverified-alerts.example.com' is not verified.")

    # 2. Uncheck and save -> succeeds (Decision A), badge shows Alerts: disabled
    checkbox.uncheck()
    save_btn.click()
    expect(error_box).to_be_hidden()
    expect(page.locator(".status-badge:has-text('Alerts: disabled')")).to_be_visible()


def test_browser_scan_detail_polling_lifecycle(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Polling starts with hx-trigger='every 3s', completes and removes polling attributes."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000006"), email="admin6@example.com")
        org = Organization(name="Scan Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="scans.example.com",
            verification_status="verified",
        )
        session.add_all([membership, domain])
        session.flush()
        scan = ScanRun(
            domain_id=domain.id,
            status="running",
            trigger="manual",
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
        )
        session.add(scan)
        session.flush()
        scan_id = scan.id
        stage = ScanStage(
            scan_run_id=scan.id,
            stage="discover",
            status="running",
            started_at=datetime.now(UTC),
        )
        session.add(stage)
        session.commit()

    sign_in(page, "admin6@example.com", live_server)
    page.locator(".btn-view-domain").click()
    page.locator("#btn-view-scans").click()
    page.locator(".btn-view-scan").click()

    container = page.locator("#scan-detail-container")
    expect(container).to_be_visible()
    expect(container).to_have_attribute("hx-trigger", "every 3s")
    expect(container).to_have_attribute("hx-get", re.compile(r"/ui/orgs/.*/scans/.*"))

    # Update scan in DB to succeeded
    with browser_session_factory() as session:
        db_scan = session.get(ScanRun, scan_id)
        if db_scan:
            db_scan.status = "succeeded"
            db_scan.finished_at = datetime.now(UTC)
            for st in db_scan.stages:
                st.status = "succeeded"
                st.finished_at = datetime.now(UTC)
            session.commit()

    # Wait for poller to auto-update
    expect(page.locator(".status-badge:has-text('Status: Succeeded')")).to_be_visible()
    container_after = page.locator("#scan-detail-container")
    expect(container_after).not_to_have_attribute("hx-trigger", re.compile(r".*"))
    expect(container_after).not_to_have_attribute("hx-get", re.compile(r".*"))


def test_browser_401_retry_preserves_single_container(
    page: Page,
    live_server: str,
    auth_events: list[dict[str, str]],
    browser_session_factory: sessionmaker[Session],
) -> None:
    """A 401 on polling triggers token refresh and retries with single #scan-detail-container."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000007"), email="admin7@example.com")
        org = Organization(name="Retry Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="retry.example.com",
            verification_status="verified",
        )
        session.add_all([membership, domain])
        session.flush()
        scan = ScanRun(
            domain_id=domain.id,
            status="running",
            trigger="manual",
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
        )
        session.add(scan)
        session.commit()
        org_id = org.id
        scan_id = scan.id

    scan_path = f"/ui/orgs/{org_id}/scans/{scan_id}"

    # a) Record every request to the scan URL with page.on("request")
    scan_requests: list[dict[str, Any]] = []

    def _on_request(req):
        if scan_path in req.url:
            scan_requests.append(
                {
                    "url": req.url,
                    "headers": req.all_headers(),
                    "auth": req.all_headers().get("authorization"),
                }
            )

    page.on("request", _on_request)

    sign_in(page, "admin7@example.com", live_server)
    page.locator(".btn-view-domain").click()
    page.locator("#btn-view-scans").click()
    page.locator(".btn-view-scan").click()

    expect(page.locator("#scan-detail-container")).to_be_visible()

    # Capture initial sign-in token
    sign_in_auth = scan_requests[0]["auth"] if scan_requests else None

    # b) Wrap the route install and the DB update inside page.expect_response for 401
    has_injected_401 = False

    def _intercept_poll(route: Route):
        nonlocal has_injected_401
        req = route.request
        if scan_path in req.url and not has_injected_401:
            has_injected_401 = True
            route.fulfill(
                status=401,
                content_type="text/plain",
                body="Unauthorized",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
            return
        route.continue_()

    with page.expect_response(lambda r: scan_path in r.url and r.status == 401):
        page.route(f"**{scan_path}", _intercept_poll)

        # c) Set the scan to succeeded in the DB
        with browser_session_factory() as session:
            db_scan = session.get(ScanRun, scan_id)
            if db_scan:
                db_scan.status = "succeeded"
                db_scan.finished_at = datetime.now(UTC)
                session.commit()

    # FIRST: expect Status: Succeeded badge to be visible
    # (guarantees retry response swapped into DOM)
    expect(page.locator(".status-badge:has-text('Status: Succeeded')")).to_be_visible()

    # IMMEDIATELY after, plain non-waiting asserts:
    assert page.locator("#scan-detail-container").count() == 1
    assert page.locator("#scan-detail-container #scan-detail-container").count() == 0
    assert page.locator("#scan-detail-container").get_attribute("hx-trigger") is None
    assert page.locator("#scan-detail-container").get_attribute("hx-get") is None

    # Auth assertions: 401 injected, refresh called once, retried request uses refreshed token
    assert has_injected_401 is True
    assert len(auth_events) == 1
    refreshed_token = auth_events[0]["new_access"]

    retried_req = scan_requests[-1]
    assert retried_req["auth"] == f"Bearer {refreshed_token}"
    assert retried_req["auth"] != sign_in_auth


def test_browser_audit_log_filters_and_paging(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Seeds 55 audit events; verifies 50 on page 1, Older events -> 5 on page 2, Newest back."""
    user_id = UUID("00000000-0000-0000-0000-000000000008")
    with browser_session_factory() as session:
        user = User(id=user_id, email="admin8@example.com")
        org = Organization(name="Audit Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="audit.example.com",
            verification_status="verified",
        )
        session.add_all([membership, domain])
        session.flush()

        # Seed 55 events with valid actions
        for i in range(55):
            action_name = "domain.created" if i % 2 == 0 else "verification.checked"
            meta = (
                {"name": f"sub{i}.example.com"}
                if i % 2 == 0
                else {"outcome": "match", "consecutive_misses": 0}
            )
            record_event(
                session=session,
                org_id=org.id,
                actor_type="user",
                actor_user_id=user.id,
                action=action_name,
                target_type="domain",
                target_id=str(domain.id),
                metadata=meta,
            )
        session.commit()

    sign_in(page, "admin8@example.com", live_server)
    page.locator("#btn-nav-audit-log").click()

    expect(page.locator("h2.panel-title:has-text('Audit log for Audit Org')")).to_be_visible()
    rows = page.locator("table.data-table tbody tr")
    expect(rows).to_have_count(50)

    older_btn = page.locator("#btn-audit-older")
    expect(older_btn).to_be_visible()
    older_btn.click()

    expect(rows).to_have_count(5)
    newest_btn = page.locator("#btn-audit-newest")
    expect(newest_btn).to_be_visible()
    newest_btn.click()

    expect(rows).to_have_count(50)

    # Test filtering by action
    action_select = page.locator("#audit-filter-action")
    action_select.select_option("domain.created")
    page.locator('#audit-filter-form button[type="submit"]').click()

    expect(page.locator("h2.panel-title:has-text('Audit log for Audit Org')")).to_be_visible()
    expect(
        page.locator("table.data-table tbody tr code:has-text('verification.checked')")
    ).to_have_count(0)


def test_browser_production_app_rejects_fake_token_401(
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """With get_current_user dependency un-overridden, fake token is rejected with 401."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-000000000009"), email="fake@example.com")
        org = Organization(name="Fake Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        session.add(membership)
        session.commit()
        org_id = org.id

    fake_token = make_fake_jwt(user)

    # Temporarily remove get_current_user override to invoke real production deps
    orig_override = app.dependency_overrides.pop(get_current_user, None)
    try:
        req = urllib.request.Request(
            f"{live_server}/ui/orgs/{org_id}/domains",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        # Close the error's response: left open, its socket was garbage-collected during
        # the next test and raised a ResourceWarning there (found with -W default).
        with exc_info.value:
            assert exc_info.value.code == 401
    finally:
        if orig_override:
            app.dependency_overrides[get_current_user] = orig_override


def test_browser_check_now_result_stays_visible(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """DNS check outcome alert stays in DOM and remains visible after network settles."""
    with browser_session_factory() as session:
        user = User(id=UUID("00000000-0000-0000-0000-00000000000a"), email="admin10@example.com")
        org = Organization(name="Check Org")
        session.add_all([user, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        domain = Domain(
            org_id=org.id,
            name="check.example.com",
            verification_status="pending",
        )
        session.add_all([membership, domain])
        session.commit()

    sign_in(page, "admin10@example.com", live_server)
    page.locator(".btn-view-domain").click()

    check_btn = page.locator("#btn-check-verification")
    expect(check_btn).to_be_visible()

    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(
            VerificationOutcome.ABSENT,
            "No TXT records found at _exposight-challenge.check.example.com",
        ),
    ) as mock_check:
        check_btn.click()

        result_box = page.locator("#verification-check-result .alert-box")
        expect(result_box).to_be_visible()
        expect(result_box).to_contain_text("Check outcome: absent")
        expect(result_box).to_contain_text(
            "No TXT records found at _exposight-challenge.check.example.com"
        )

        # Ensure outcome stays in DOM and doesn't get cleared by subsequent renders
        page.wait_for_load_state("networkidle")
        expect(result_box).to_be_visible()
        expect(result_box).to_contain_text("Check outcome: absent")

        assert mock_check.call_count == 1


# Landing page (C-UI-1): motion is CSS only (load animation, scroll-driven reveals,
# pinned "How it works"). These elements must end up visible with opacity 1.
ANIMATED_SELECTORS = [
    ".hero-copy > *",
    ".hero-card",
    ".pipeline-stage-node",
    ".stage-step-card",
    ".feature-item",
    ".recon-panel",
    ".inventory",
    ".topology",
    ".trust-code-chassis",
    ".cta-container > *",
]

_ALL_OPAQUE_JS = """
(selectors) => selectors.every((sel) => {
    const els = document.querySelectorAll(sel);
    return els.length > 0 && [...els].every((el) => getComputedStyle(el).opacity === "1");
})
"""


def _assert_all_visible_and_opaque(page: Page, selectors: list[str]) -> None:
    # The hero load animation takes about 1.4 s; wait for it instead of sampling mid-way.
    # Polled from Python: wait_for_function cannot poll in a page with JavaScript disabled.
    for _ in range(40):
        if page.evaluate(_ALL_OPAQUE_JS, selectors):
            break
        page.wait_for_timeout(200)
    for sel in selectors:
        loc = page.locator(sel)
        count = loc.count()
        assert count > 0, f"No elements matched for selector {sel}"
        for i in range(count):
            el = loc.nth(i)
            expect(el).to_be_visible()
            opacity = el.evaluate("e => window.getComputedStyle(e).opacity")
            assert opacity == "1", f"Opacity not 1 for {sel}[{i}]"


def test_browser_landing_page_loads_with_css_motion_and_no_external_requests(
    page: Page,
    live_server: str,
) -> None:
    """Landing loads with 0 CSP violations (fixture), only same-origin requests, no GSAP,
    and the scroll-driven reveal wired to a view() timeline in this Chromium."""
    requests: list[str] = []
    page.on("request", lambda req: requests.append(req.url))
    page.goto(f"{live_server}/")
    expect(page.locator("#hero h1")).to_be_visible()
    page.wait_for_load_state("networkidle")

    external = [url for url in requests if not url.startswith(live_server)]
    assert external == [], f"Landing page requested external origins: {external}"
    for font_file in ("PlusJakartaSans-Variable.woff2", "Inter-Variable.woff2"):
        assert any(url.endswith(f"/static/fonts/{font_file}") for url in requests), font_file
    assert page.evaluate("typeof window.gsap") == "undefined"

    assert page.evaluate("CSS.supports('animation-timeline: view()')") is True
    timeline = page.locator(".stage-step-card").first.evaluate(
        "e => getComputedStyle(e).animationTimeline"
    )
    assert "view" in timeline
    font = page.locator(".hero-title").evaluate("e => getComputedStyle(e).fontFamily")
    assert "Plus Jakarta Sans" in font
    body_font = page.locator(".hero-subhead").evaluate("e => getComputedStyle(e).fontFamily")
    assert body_font.startswith('"Inter"') or body_font.startswith("Inter")
    assert page.evaluate("document.fonts.check('700 16px \"Plus Jakarta Sans\"')") is True


def test_browser_landing_page_reduced_motion(
    make_page,
    live_server: str,
) -> None:
    """With reducedMotion='reduce', no animation runs, nothing is tilted, and every step of
    "How it works" is shown as a plain list (not pinned)."""
    with make_page(reduced_motion="reduce") as page:
        page.goto(f"{live_server}/")

        for sel in [*ANIMATED_SELECTORS, ".how-card"]:
            loc = page.locator(sel)
            count = loc.count()
            assert count > 0, f"No elements matched for selector {sel}"
            for i in range(count):
                el = loc.nth(i)
                expect(el).to_be_visible()
                style = el.evaluate(
                    "e => { const c = getComputedStyle(e);"
                    " return [c.opacity, c.transform, c.animationName, c.position]; }"
                )
                opacity, transform, animation_name, position = style
                assert opacity == "1", f"Opacity not 1 for {sel}[{i}]"
                assert transform in ("none", "matrix(1, 0, 0, 1, 0, 0)"), (
                    f"Transform not none for {sel}[{i}]: {transform}"
                )
                assert animation_name == "none", f"Animation still on for {sel}[{i}]"
                assert position != "absolute", f"{sel}[{i}] is still pinned/stacked"


def test_browser_landing_page_no_js(
    make_page,
    live_server: str,
) -> None:
    """With JavaScript disabled, all animated elements remain fully visible."""
    with make_page(java_script_enabled=False) as page:
        page.goto(f"{live_server}/")
        _assert_all_visible_and_opaque(page, ANIMATED_SELECTORS)


def test_browser_landing_all_sections_reveal_on_scroll(
    page: Page,
    live_server: str,
) -> None:
    """Full motion: scrolling through every section leaves every animated element visible."""
    page.goto(f"{live_server}/")

    for sec in [
        "#hero",
        "#surface",
        "#how-it-works",
        "#pipeline",
        "#features",
        "#ownership",
        "#cta",
    ]:
        page.locator(sec).scroll_into_view_if_needed()
        page.wait_for_timeout(100)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(200)

    _assert_all_visible_and_opaque(page, ANIMATED_SELECTORS)


def test_browser_landing_how_it_works_is_pinned_on_wide_screens(
    page: Page,
    live_server: str,
) -> None:
    """The four steps play as a pinned sequence: mid-way through, one card is in focus."""
    page.goto(f"{live_server}/")
    section = page.locator("#how-it-works")
    top = section.evaluate("e => e.getBoundingClientRect().top + window.scrollY")
    height = section.evaluate("e => e.offsetHeight")
    viewport = page.evaluate("window.innerHeight")
    assert height > 1.5 * viewport, "How it works is not tall enough to pin"

    # Scroll to the middle of the second step's range.
    page.evaluate(f"window.scrollTo(0, {top} + ({height} - {viewport}) * 0.37)")
    page.wait_for_timeout(300)
    opacities = page.locator(".how-card").evaluate_all(
        "els => els.map(e => parseFloat(getComputedStyle(e).opacity))"
    )
    assert opacities[1] > 0.95, opacities
    assert opacities[0] < 0.05 and opacities[3] < 0.05, opacities
    sticky = page.locator(".how-sticky").evaluate("e => getComputedStyle(e).position")
    assert sticky == "sticky"


def test_browser_landing_how_it_works_has_no_empty_stretch(
    page: Page,
    live_server: str,
) -> None:
    """C-UI-2: the pinned section is at most 2 viewports tall (so a full-page render shows
    under one viewport of empty space below the pinned frame), and at every scroll step
    through it one step card is in focus."""
    page.goto(f"{live_server}/")
    section = page.locator("#how-it-works")
    top = section.evaluate("e => e.getBoundingClientRect().top + window.scrollY")
    height = section.evaluate("e => e.offsetHeight")
    viewport = page.evaluate("window.innerHeight")
    assert height <= 2 * viewport + 1, f"pinned section {height}px for viewport {viewport}px"

    for step in range(21):
        page.evaluate(f"window.scrollTo(0, {top} + ({height} - {viewport}) * {step / 20})")
        page.wait_for_timeout(60)
        best = page.locator(".how-card").evaluate_all(
            "els => Math.max(...els.map(e => parseFloat(getComputedStyle(e).opacity)))"
        )
        assert best > 0.6, f"no step card in focus at {step * 5}% of the pinned range"


def test_browser_landing_pill_nav_marks_active_section(
    page: Page,
    live_server: str,
) -> None:
    """C-UI-2: the floating pill nav stays hidden over the hero, appears once the hero is
    scrolled past, highlights the section in view, and is never shown below 480 px."""
    page.goto(f"{live_server}/")
    pill_nav = page.locator(".pill-nav")
    expect(pill_nav).to_be_hidden()

    page.evaluate("document.querySelector('#features').scrollIntoView({block: 'center'})")
    expect(pill_nav).to_be_visible()
    active = page.locator(".pill-nav-link.is-active")
    expect(active).to_have_count(1)
    expect(active).to_have_attribute("href", "#features")
    expect(active).to_have_attribute("aria-current", "true")

    page.evaluate("window.scrollTo(0, 0)")
    expect(pill_nav).to_be_hidden()

    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("document.querySelector('#features').scrollIntoView({block: 'center'})")
    expect(pill_nav).to_be_hidden()


def test_browser_landing_pill_nav_reduced_motion_and_no_js(
    make_page,
    live_server: str,
) -> None:
    """Reduced motion: the pill nav shows past the hero with no transition. Without
    JavaScript it is always visible, so section links still work."""
    with make_page(reduced_motion="reduce") as page:
        page.goto(f"{live_server}/")
        pill_nav = page.locator(".pill-nav")
        expect(pill_nav).to_be_hidden()
        page.evaluate("document.querySelector('#features').scrollIntoView({block: 'center'})")
        expect(pill_nav).to_be_visible()
        transition = pill_nav.evaluate("e => getComputedStyle(e).transitionDuration")
        assert set(transition.replace(" ", "").split(",")) == {"0s"}, transition

    with make_page(java_script_enabled=False) as page:
        page.goto(f"{live_server}/")
        expect(page.locator(".pill-nav")).to_be_visible()


def test_browser_landing_signin_label_reflects_session_key(
    make_page,
    live_server: str,
) -> None:
    """C-UI-4: the header label reads "Open dashboard" only when a Supabase session key is in
    sessionStorage; no key, JavaScript off, or a throwing sessionStorage keep "Sign in".
    make_page fails the test on page errors, CSP violations and off-origin requests."""
    label = ".landing-header .landing-signin-btn"

    with make_page() as page:
        page.add_init_script("sessionStorage.setItem('sb-test-auth-token', 'dummy');")
        page.goto(f"{live_server}/")
        expect(page.locator(label)).to_have_text("Open dashboard")
        expect(page.locator(label)).to_have_attribute("href", "/app")
        assert page.evaluate("window.__cspViolations.length") == 0

    with make_page() as page:
        page.add_init_script("sessionStorage.setItem('unrelated-key', 'x');")
        page.goto(f"{live_server}/")
        page.wait_for_load_state("load")
        expect(page.locator(label)).to_have_text("Sign in")

    with make_page() as page:
        page.add_init_script(
            "Object.defineProperty(window, 'sessionStorage', "
            "{get() { throw new Error('storage blocked'); }});"
        )
        page.goto(f"{live_server}/")
        page.wait_for_load_state("load")
        expect(page.locator(label)).to_have_text("Sign in")

    with make_page(java_script_enabled=False) as page:
        page.goto(f"{live_server}/")
        expect(page.locator(label)).to_have_text("Sign in")


def test_browser_landing_page_cta_navigation(
    page: Page,
    live_server: str,
) -> None:
    """Clicking 'Get started' CTA button navigates to /app and shows sign-in form."""
    page.goto(f"{live_server}/")
    expect(page.locator(".cta-btn")).to_be_visible()
    page.locator(".cta-btn").click()

    expect(page.locator("#auth-section")).to_be_visible()
    expect(page.locator("#signin-form")).to_be_visible()
    assert "/app" in page.url


def test_browser_terms_page_linked_from_landing_footer(
    page: Page,
    live_server: str,
) -> None:
    """v3.6b A8: the landing footer links to /terms, which renders under the strict CSP."""
    page.goto(f"{live_server}/")
    link = page.locator("footer a[href='/terms']")
    expect(link).to_be_visible()
    link.click()

    expect(page.locator("#terms-title")).to_have_text("Terms & Acceptable Use")
    expect(page.locator("main")).to_contain_text("Only scan what you own")
    assert page.url.endswith("/terms")


def test_browser_suspended_account_sees_notice_without_reason(
    make_page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """v3.6c B-4: a suspended account sees "Account suspended" and nothing of the reason."""
    from datetime import UTC, datetime

    reason = "Internal note OPS-9001: scanned third parties"
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            email="owner@example.com",
            suspended_at=datetime.now(UTC),
            suspended_reason=reason,
        )
        org = Organization(name="Acme Corp")
        session.add_all([user, org])
        session.flush()
        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        session.commit()

    with make_page(allowed_error_statuses=(403,)) as page:
        sign_in(page, "owner@example.com", live_server)

        panel = page.locator("#suspended-panel")
        expect(panel).to_be_visible()
        expect(page.locator("#suspended-title")).to_have_text("Account suspended")
        expect(page.locator("#main-content-area")).to_be_empty()
        expect(page.locator("#signout-button")).to_be_visible()
        assert "OPS-9001" not in page.content()

        # Sign-out hides the notice again.
        page.locator("#signout-button").click()
        expect(page.locator("#auth-section")).to_be_visible()
        expect(panel).to_be_hidden()


def test_browser_scan_detail_changes_and_baseline_rendering(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Verifies baseline scan detail (no changes) vs subsequent scan detail with
    production-consistent change fixtures (category='exposure', real severities,
    real details/evidence) referencing two distinct historical baseline scans.

    UI exposure scope:
    - partials/scan_detail.html displays run-level baseline context and columns for
      Severity, Category, Change type, Asset, Detail, Evidence.
    - Per-change baseline_scan_run_id attribution is persisted in the database and
      returned via REST API, but the existing UI does not render a per-row baseline link.
    - Viewer UI behavior: #btn-run-scan is omitted from DOM for viewers (server-side
      RBAC enforcement is tested in tests/test_route_isolation_db.py).
    """
    with browser_session_factory() as session:
        viewer = User(
            id=UUID("00000000-0000-0000-0000-000000000020"),
            email="viewer20@example.com",
        )
        org = Organization(name="Changes Verification Org")
        session.add_all([viewer, org])
        session.flush()
        membership = Membership(org_id=org.id, user_id=viewer.id, role="viewer")
        domain = Domain(
            org_id=org.id,
            name="changes.example.com",
            verification_status="verified",
        )
        session.add_all([membership, domain])
        session.flush()

        # 1. Historical baseline scan 1 (earlier scan)
        baseline_scan_1 = ScanRun(
            domain_id=domain.id,
            status="succeeded",
            trigger="manual",
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        session.add(baseline_scan_1)
        session.flush()

        # 2. Historical baseline scan 2 (intermediate scan)
        baseline_scan_2 = ScanRun(
            domain_id=domain.id,
            status="succeeded",
            trigger="manual",
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        session.add(baseline_scan_2)
        session.flush()

        # 3. Subsequent scan with accumulated scanner changes
        subsequent_scan = ScanRun(
            domain_id=domain.id,
            status="succeeded",
            trigger="manual",
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        session.add(subsequent_scan)
        session.flush()

        now = datetime.now(UTC)
        changes = [
            # Discovery removal: severity='INFO', detail='', evidence='discover'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_1.id,
                change_type="REMOVED_SUBDOMAIN",
                category="exposure",
                severity="INFO",
                asset="stale.changes.example.com",
                detail="",
                evidence="discover",
                previous_state={"status": "RESOLVED", "resolved": True},
                new_state=None,
                observed_at=now,
            ),
            # Discovery addition: severity='INFO', detail='', evidence='discover'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_1.id,
                change_type="NEW_SUBDOMAIN",
                category="exposure",
                severity="INFO",
                asset="new.changes.example.com",
                detail="",
                evidence="discover",
                previous_state=None,
                new_state={"status": "RESOLVED", "resolved": True},
                observed_at=now,
            ),
            # HTTPS lost: severity='MEDIUM', detail='', evidence='probe'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_1.id,
                change_type="HTTPS_LOST",
                category="exposure",
                severity="MEDIUM",
                asset="secure.changes.example.com",
                detail="",
                evidence="probe",
                previous_state={"https_reachable": True},
                new_state={"https_reachable": False, "error_type": "CONNECT_ERROR"},
                observed_at=now,
            ),
            # Port newly open: severity='HIGH' (RDP 3389), detail='3389', evidence='portscan'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_2.id,
                change_type="PORT_NEWLY_OPEN",
                category="exposure",
                severity="HIGH",
                asset="vpn.changes.example.com",
                detail="3389",
                evidence="portscan",
                previous_state={"port": 3389, "state": "CLOSED"},
                new_state={"port": 3389, "state": "OPEN", "service": "ms-wbt-server"},
                observed_at=now,
            ),
            # Certificate changed: severity='INFO', detail='issuer', evidence='inspect'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_2.id,
                change_type="CERTIFICATE_CHANGED",
                category="exposure",
                severity="INFO",
                asset="api.changes.example.com",
                detail="issuer",
                evidence="inspect",
                previous_state={"issuer": "CN=Old CA"},
                new_state={"issuer": "CN=New CA"},
                observed_at=now,
            ),
            # Header weakened: severity='LOW', detail='HSTS', evidence='inspect'
            ScanChange(
                domain_id=domain.id,
                scan_run_id=subsequent_scan.id,
                baseline_scan_run_id=baseline_scan_2.id,
                change_type="SECURITY_HEADER_WEAKENED",
                category="exposure",
                severity="LOW",
                asset="api.changes.example.com",
                detail="Strict-Transport-Security",
                evidence="inspect",
                previous_state={"header": "Strict-Transport-Security", "status": "strong"},
                new_state={"finding_id": "HEADER_WEAK_HSTS", "evidence": "max-age=300"},
                observed_at=now,
            ),
        ]
        session.add_all(changes)
        session.commit()

        b1_id = baseline_scan_1.id
        s_id = subsequent_scan.id

    # Sign in as viewer
    sign_in(page, "viewer20@example.com", live_server)
    page.locator(".btn-view-domain").click()
    page.locator("#btn-view-scans").click()

    # Viewer UI behavior: viewer cannot run scans (Run scan button omitted from DOM)
    expect(page.locator("#btn-run-scan")).to_have_count(0)

    # 1. View baseline scan (which has zero changes)
    page.locator(f"button.btn-view-scan[data-scan-id='{b1_id}']").click()
    scan_detail = page.locator("#scan-detail-container")
    expect(scan_detail).to_be_visible()
    expect(scan_detail).to_contain_text("No changes detected in this scan.")

    # 2. Navigate back to scans list and view subsequent scan
    page.locator("#btn-back-scans").click()
    page.locator(f"button.btn-view-scan[data-scan-id='{s_id}']").click()

    # 3. Subsequent scan shows changes table
    expect(scan_detail).to_be_visible()
    expect(scan_detail).not_to_contain_text("No changes detected in this scan.")

    # Check each change type rendered in code elements
    expect(page.locator("code:has-text('REMOVED_SUBDOMAIN')")).to_be_visible()
    expect(page.locator("code:has-text('NEW_SUBDOMAIN')")).to_be_visible()
    expect(page.locator("code:has-text('HTTPS_LOST')")).to_be_visible()
    expect(page.locator("code:has-text('PORT_NEWLY_OPEN')")).to_be_visible()
    expect(page.locator("code:has-text('CERTIFICATE_CHANGED')")).to_be_visible()
    expect(page.locator("code:has-text('SECURITY_HEADER_WEAKENED')")).to_be_visible()

    # Check assets
    expect(page.locator("code:has-text('stale.changes.example.com')")).to_be_visible()
    expect(page.locator("code:has-text('new.changes.example.com')")).to_be_visible()
    expect(page.locator("code:has-text('secure.changes.example.com')")).to_be_visible()
    expect(page.locator("code:has-text('vpn.changes.example.com')")).to_be_visible()

    # Check details matching production detector output
    expect(page.locator("td:has-text('3389')")).to_be_visible()
    expect(page.locator("td:has-text('Strict-Transport-Security')")).to_be_visible()
    expect(page.locator("td:has-text('issuer')")).to_be_visible()

    # Check evidence codes
    expect(page.locator("code:has-text('discover')")).to_have_count(2)
    expect(page.locator("code:has-text('probe')")).to_be_visible()
    expect(page.locator("code:has-text('portscan')")).to_be_visible()
    expect(page.locator("code:has-text('inspect')")).to_have_count(2)

    # Check real production severities
    expect(page.locator(".tier-badge.tier-high:has-text('High')")).to_be_visible()
    expect(page.locator(".tier-badge.tier-medium:has-text('Medium')")).to_be_visible()
    expect(page.locator(".tier-badge.tier-low:has-text('Low')")).to_be_visible()
    expect(page.locator(".tier-badge.tier-info:has-text('Info')")).to_have_count(3)
