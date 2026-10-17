"""Playwright browser tests for tenant switching, session transitions, and logout.

Verifies runtime browser behavior:
1. Start an Org A request, switch to Org B, release delayed A: A's content must not render.
2. Release an old response after logout: protected content and user email remain cleared.
3. Release stale 403/404 responses after switching organizations: no misleading error in Org B.
4. Normal navigation, refresh, and same-organization responses work smoothly.
5. Viewport responsiveness (desktop & 390px mobile) and keyboard focus navigation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from uuid import UUID

import pytest
from playwright.sync_api import Page, Route, expect
from sqlalchemy.orm import Session, sessionmaker

from asm.db.models import Domain, Membership, Organization, ScanRun, ScanStage, User
from tests.browser.helpers import make_fake_jwt, sign_in

pytestmark = pytest.mark.browser


def test_browser_org_switching_delayed_response_not_rendered(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Delayed response from Org A must be dropped when Org B is active using real responses."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000091"),
            email="tenant-switch@example.com",
        )
        org_a = Organization(name="Tenant Alpha")
        org_b = Organization(name="Tenant Beta")
        session.add_all([user, org_a, org_b])
        session.flush()

        session.add(Membership(org_id=org_a.id, user_id=user.id, role="owner"))
        session.add(Membership(org_id=org_b.id, user_id=user.id, role="owner"))

        domain_a = Domain(
            org_id=org_a.id,
            name="alpha-confidential.example.com",
            verification_status="verified",
            verification_token="tok-a",
        )
        domain_b = Domain(
            org_id=org_b.id,
            name="beta-public.example.com",
            verification_status="verified",
            verification_token="tok-b",
        )
        session.add_all([domain_a, domain_b])
        session.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    # Wait for org switcher to load options and Org A to be initially active
    expect(page.locator("#org-switcher-select option")).to_have_count(2)
    expect(page.locator("text=alpha-confidential.example.com")).to_be_visible()

    # Case 1: Intercept Org A request with X-Origin-Org-Id header present
    held_routes: list[Route] = []
    holding_active = True

    def _hold_org_a(route: Route):
        nonlocal holding_active
        if holding_active and f"/ui/orgs/{org_a_id}/" in route.request.url:
            holding_active = False
            held_routes.append(route)
        else:
            route.fallback()

    page.route(re.compile(rf".*/ui/orgs/{org_a_id}/.*"), _hold_org_a)

    # Trigger an in-flight request to Org A domains using arrow function
    page.evaluate(
        "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
        f"/ui/orgs/{org_a_id}/domains",
    )
    page.wait_for_timeout(200)
    assert len(held_routes) == 1, "Expected in-flight Org A request to be held"

    # Now user switches to Org B
    page.select_option("#org-switcher-select", str(org_b_id))
    expect(page.locator("text=beta-public.example.com")).to_be_visible()

    # Release held Org A response directly to live server (real application response, not synthetic)
    held = held_routes.pop(0)
    held.continue_()
    page.wait_for_timeout(300)

    # Assert Org A content was dropped by beforeSwap guard and not rendered; Org B remains active
    expect(page.locator("text=alpha-confidential.example.com")).not_to_be_visible()
    expect(page.locator("text=beta-public.example.com")).to_be_visible()

    # Case 2: Missing X-Origin-Org-Id header fallback (uses URL path regex /^\/ui\/orgs\/(\d+)\//)
    page.unroute(re.compile(rf".*/ui/orgs/{org_a_id}/.*"))
    held_missing_header: list[Route] = []
    page.route(
        re.compile(rf".*/ui/orgs/{org_a_id}/domains.*"),
        lambda route: held_missing_header.append(route),
    )

    # Trigger HTMX request where configRequest explicitly deletes X-Origin-Org-Id header
    page.evaluate(
        """(path) => {
            const stripHeader = function(evt) {
                delete evt.detail.headers['X-Origin-Org-Id'];
                document.body.removeEventListener('htmx:configRequest', stripHeader);
            };
            document.body.addEventListener('htmx:configRequest', stripHeader);
            window.htmx.ajax('GET', path, '#main-content-area');
        }""",
        f"/ui/orgs/{org_a_id}/domains",
    )
    page.wait_for_timeout(200)
    assert len(held_missing_header) == 1, "Expected missing-header request to be held"

    missing_header_route = held_missing_header.pop(0)
    missing_header_route.continue_()
    page.wait_for_timeout(300)

    # URL path regex fallback identified org_a_id and successfully blocked swapping into Org B
    expect(page.locator("text=alpha-confidential.example.com")).not_to_be_visible()
    expect(page.locator("text=beta-public.example.com")).to_be_visible()


def test_browser_delayed_response_after_logout_cleared(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Delayed response arriving after sign out must not render into DOM and email stays cleared."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000092"),
            email="logout-delayed@example.com",
        )
        org = Organization(name="Logout Org")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="logout-test.example.com",
            verification_status="verified",
            verification_token="tok-l",
        )
        session.add(domain)
        session.commit()
        org_id = org.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    expect(page.locator("#org-switcher-select option")).to_have_count(1)
    expect(page.locator("text=logout-test.example.com")).to_be_visible()
    expect(page.locator("#user-email-display")).to_have_text("logout-delayed@example.com")

    # Hold the next request
    held_routes: list[Route] = []
    holding_active = True

    def _hold_domains(route: Route):
        nonlocal holding_active
        if holding_active and f"/ui/orgs/{org_id}/domains" in route.request.url:
            holding_active = False
            held_routes.append(route)
        else:
            route.fallback()

    page.route(re.compile(rf".*/ui/orgs/{org_id}/domains.*"), _hold_domains)

    # Start an HTMX request
    page.evaluate(
        "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
        f"/ui/orgs/{org_id}/domains",
    )
    page.wait_for_timeout(200)
    assert len(held_routes) == 1

    # User clicks Sign out (id="signout-button")
    page.locator("#signout-button").click()
    expect(page.locator("#auth-section")).to_be_visible()
    expect(page.locator("#app-shell")).to_be_hidden()
    expect(page.locator("#user-email-display")).to_have_text("")

    # Release held response with sensitive HTML
    held = held_routes.pop(0)
    held.fulfill(
        status=200,
        content_type="text/html",
        body='<div id="stale-post-logout-marker">UNAUTHORIZED POST LOGOUT LEAK</div>',
    )
    page.wait_for_timeout(300)

    # Marker must not attach, app-shell stays hidden, user display stays cleared
    expect(page.locator("#stale-post-logout-marker")).not_to_be_attached()
    expect(page.locator("#app-shell")).to_be_hidden()
    expect(page.locator("#user-email-display")).to_have_text("")


def test_browser_stale_errors_after_org_switch_dropped(
    make_page: Callable[..., AbstractContextManager[Page]],
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Stale 403 or 404 errors from previous tenant must not surface error banners in new tenant."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000093"),
            email="stale-err@example.com",
        )
        org_1 = Organization(name="Org One")
        org_2 = Organization(name="Org Two")
        session.add_all([user, org_1, org_2])
        session.flush()

        session.add(Membership(org_id=org_1.id, user_id=user.id, role="owner"))
        session.add(Membership(org_id=org_2.id, user_id=user.id, role="owner"))

        domain_1 = Domain(
            org_id=org_1.id,
            name="org1-dom.example.com",
            verification_status="verified",
            verification_token="tok-1",
        )
        domain_2 = Domain(
            org_id=org_2.id,
            name="org2-dom.example.com",
            verification_status="verified",
            verification_token="tok-2",
        )
        session.add_all([domain_1, domain_2])
        session.commit()
        org_1_id = org_1.id
        org_2_id = org_2.id

    make_fake_jwt(user)

    with make_page(allowed_error_statuses=(404, 403)) as page:
        sign_in(page, user.email, live_server)

        expect(page.locator("#org-switcher-select option")).to_have_count(2)
        page.select_option("#org-switcher-select", str(org_1_id))
        expect(page.locator("text=org1-dom.example.com")).to_be_visible()

        held_routes: list[Route] = []
        holding_active = True

        def _hold_err(route: Route):
            nonlocal holding_active
            if holding_active and f"/ui/orgs/{org_1_id}/domains/99999" in route.request.url:
                holding_active = False
                held_routes.append(route)
            else:
                route.fallback()

        page.route(re.compile(rf".*/ui/orgs/{org_1_id}/domains/99999.*"), _hold_err)

        # Start a request in Org 1 that will 404
        page.evaluate(
            "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
            f"/ui/orgs/{org_1_id}/domains/99999",
        )
        page.wait_for_timeout(200)
        assert len(held_routes) == 1

        # Switch to Org 2
        page.select_option("#org-switcher-select", str(org_2_id))
        expect(page.locator("text=org2-dom.example.com")).to_be_visible()

        # Release the Org 1 404 error
        held = held_routes.pop(0)
        held.fulfill(
            status=404,
            content_type="application/json",
            body='{"detail": "Domain not found in Org 1"}',
        )
        page.wait_for_timeout(300)

        # Global error box must remain hidden (no false alarm in Org 2)
        error_box = page.locator("#global-error-box")
        expect(error_box).to_have_class("alert-box alert-error hidden")
        expect(page.locator("text=org2-dom.example.com")).to_be_visible()


def test_browser_responsive_and_keyboard_navigation(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Verifies layout integrity at 390px mobile viewport and keyboard focus navigation."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000094"),
            email="responsive@example.com",
        )
        org = Organization(name="Responsive Org")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="mobile-view.example.com",
            verification_status="verified",
            verification_token="tok-resp",
        )
        session.add(domain)
        session.commit()

    make_fake_jwt(user)

    # Test at 390px mobile width
    page.set_viewport_size({"width": 390, "height": 844})
    sign_in(page, user.email, live_server)

    expect(page.locator("#app-shell")).to_be_visible()
    expect(page.locator("text=mobile-view.example.com")).to_be_visible()

    # Keyboard navigation check: Focus select, tab to signout button
    org_select = page.locator("#org-switcher-select")
    org_select.focus()
    page.keyboard.press("Tab")
    signout_btn = page.locator("#signout-button")
    expect(signout_btn).to_be_focused()

    # Tab into main content
    page.keyboard.press("Tab")
    active_tag = page.evaluate("document.activeElement.tagName")
    assert active_tag in ("BUTTON", "SELECT", "INPUT", "A")

    # Reset to desktop viewport
    page.set_viewport_size({"width": 1280, "height": 720})
    expect(page.locator("text=mobile-view.example.com")).to_be_visible()


def test_browser_delayed_response_logout_relogin_same_org_dropped(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Delayed response from session 1 arriving after logout and relogin to same org is dropped."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000095"),
            email="relogin-same-org@example.com",
        )
        org = Organization(name="Same Org Multi Session")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="initial-state.example.com",
            verification_status="verified",
            verification_token="tok-relogin",
        )
        session.add(domain)
        session.commit()
        org_id = org.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    expect(page.locator("text=initial-state.example.com")).to_be_visible()

    # Track dropped swaps in the page context
    page.evaluate(
        """() => {
            window.__droppedSwaps = 0;
            document.body.addEventListener('htmx:beforeSwap', function(evt) {
                if (evt.detail.shouldSwap === false) {
                    window.__droppedSwaps++;
                }
            });
        }"""
    )

    # Intercept and hold an in-flight request to /ui/orgs/{org_id}/domains
    held_routes: list[Route] = []
    holding_active = True

    def _hold_domains(route: Route):
        nonlocal holding_active
        if holding_active and f"/ui/orgs/{org_id}/domains" in route.request.url:
            holding_active = False
            held_routes.append(route)
        else:
            route.fallback()

    page.route(re.compile(rf".*/ui/orgs/{org_id}/domains.*"), _hold_domains)

    # Start an HTMX request in session 1
    page.evaluate(
        "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
        f"/ui/orgs/{org_id}/domains",
    )
    page.wait_for_timeout(200)
    assert len(held_routes) == 1, "Expected session 1 request to be held"

    # User signs out
    page.locator("#signout-button").click()
    expect(page.locator("#auth-section")).to_be_visible()
    expect(page.locator("#app-shell")).to_be_hidden()

    # Remove the route interceptor so sign_in for session 2 can complete its own requests
    page.unroute(re.compile(rf".*/ui/orgs/{org_id}/domains.*"))

    # User logs in again via in-page signin form (preserving SPA document context)
    page.locator("#signin-email").fill(user.email)
    page.locator("#signin-password").fill("ValidPassword123!")
    page.locator('#signin-form button[type="submit"]').click()
    expect(page.locator("#app-shell")).to_be_visible()
    expect(
        page.locator("table.data-table strong:has-text('initial-state.example.com')")
    ).to_be_visible()

    # Track dropped swaps in session 2
    page.evaluate(
        """() => {
            window.__droppedSwaps = 0;
            document.body.addEventListener('htmx:beforeSwap', function(evt) {
                if (evt.detail.shouldSwap === false) {
                    window.__droppedSwaps++;
                }
            });
        }"""
    )

    # Place a distinct DOM sentinel in #main-content-area to ensure it is not overwritten
    page.evaluate(
        """() => {
            const marker = document.createElement('div');
            marker.id = 'session-2-sentinel';
            marker.textContent = 'Session 2 Active State';
            document.getElementById('main-content-area').prepend(marker);
        }"""
    )
    expect(page.locator("#session-2-sentinel")).to_be_visible()

    # Release held session 1 request via continue_() (actual live server response)
    held = held_routes.pop(0)
    held.continue_()
    page.wait_for_timeout(400)

    # Verify session 1 response was dropped by htmx:beforeSwap (epoch mismatch)
    # The session 2 sentinel must NOT have been wiped out / overwritten
    expect(page.locator("#session-2-sentinel")).to_be_visible()
    dropped_count = page.evaluate("() => window.__droppedSwaps")
    assert dropped_count >= 1, f"Expected at least 1 dropped swap, got {dropped_count}"


def test_browser_same_org_navigation_and_polling(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """Verifies same-organization navigation and polling updates without interference."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-000000000096"),
            email="same-org-nav@example.com",
        )
        org = Organization(name="Navigation Org")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="nav-domain.example.com",
            verification_status="verified",
            verification_token="tok-nav",
        )
        session.add(domain)
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

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    # 1. On domains list, verify domain is visible
    expect(
        page.locator("table.data-table strong:has-text('nav-domain.example.com')")
    ).to_be_visible()

    # 2. Navigate to domain detail
    page.locator(".btn-view-domain").click()
    expect(page.locator("h2.panel-title:has-text('nav-domain.example.com')")).to_be_visible()
    expect(page.locator("#btn-back-domains")).to_be_visible()

    # 3. Navigate to scans list
    page.locator("#btn-view-scans").click()
    expect(
        page.locator("h2.panel-title:has-text('Scans for nav-domain.example.com')")
    ).to_be_visible()

    # 4. Navigate into scan detail
    page.locator(".btn-view-scan").click()
    scan_container = page.locator("#scan-detail-container")
    expect(scan_container).to_be_visible()
    expect(scan_container).to_have_attribute("hx-trigger", "every 3s")
    expect(page.locator(".status-badge:has-text('Status: Running')")).to_be_visible()

    # 5. Polling update: mark scan succeeded in DB
    with browser_session_factory() as session:
        db_scan = session.get(ScanRun, scan_id)
        if db_scan:
            db_scan.status = "succeeded"
            db_scan.finished_at = datetime.now(UTC)
            for st in db_scan.stages:
                st.status = "succeeded"
                st.finished_at = datetime.now(UTC)
            session.commit()

    # Auto-poll receives update, swaps container, and stops polling
    expect(page.locator(".status-badge:has-text('Status: Succeeded')")).to_be_visible()
    expect(page.locator("#scan-detail-container")).not_to_have_attribute(
        "hx-trigger", re.compile(r".*")
    )

    # 6. Back navigation: back to scans list, then back to domain detail, then back to domains list
    page.locator("#btn-back-scans").click()
    expect(
        page.locator("h2.panel-title:has-text('Scans for nav-domain.example.com')")
    ).to_be_visible()
    page.locator("#btn-back-domain-detail").click()
    expect(page.locator("h2.panel-title:has-text('nav-domain.example.com')")).to_be_visible()
    page.locator("#btn-back-domains").click()
    expect(
        page.locator("table.data-table strong:has-text('nav-domain.example.com')")
    ).to_be_visible()
