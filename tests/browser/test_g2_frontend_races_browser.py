"""Playwright browser tests reproducing G2 frontend asynchronous session and organization races.

Verifies:
1. G2.1: Request-path org vs X-Origin-Org-Id mismatch:
   When an in-flight or delayed HTMX request targets Org A while currentSelectedOrgId is Org B,
   X-Origin-Org-Id must not shadow the URL path or allow swapping Org A's content into Org B.
2. G2.2: Action continuations after org switch or logout:
   When an action (POST/PUT via authenticatedFetch) finishes after the user switched orgs
   or logged out, the continuation must not trigger a new GET for the old org or mutate DOM.
3. G2.3: loadOrgSwitcher after logout:
   When GET /orgs resolves after the user logged out, it must not populate the org switcher,
   set currentSelectedOrgId, or trigger loadDomainsList.
4. G2.3: 401 refresh/retry after org switch or logout:
   When a session refresh completes after logout or org switch, it must not restore access
   tokens or retry requests for the wrong session/org.
"""

from __future__ import annotations

import json
import re
from uuid import UUID

import pytest
from playwright.sync_api import Page, Route, expect
from sqlalchemy.orm import Session, sessionmaker

from asm.db.models import Domain, Membership, Organization, User
from tests.browser.helpers import make_fake_jwt, sign_in

pytestmark = pytest.mark.browser


def test_g2_1_request_path_org_vs_header_mismatch_browser(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """G2.1: Request-path org must not be shadowed by X-Origin-Org-Id when switching orgs."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-0000000000a1"),
            email="g2-path-mismatch@example.com",
        )
        org_a = Organization(name="Tenant Alpha G21")
        org_b = Organization(name="Tenant Beta G21")
        session.add_all([user, org_a, org_b])
        session.flush()

        session.add(Membership(org_id=org_a.id, user_id=user.id, role="owner"))
        session.add(Membership(org_id=org_b.id, user_id=user.id, role="owner"))

        domain_a = Domain(
            org_id=org_a.id,
            name="alpha-secret.example.com",
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

    expect(page.locator("#org-switcher-select option")).to_have_count(2)
    # Switch to Org B so currentSelectedOrgId is Org B
    page.select_option("#org-switcher-select", str(org_b_id))
    expect(page.locator("text=beta-public.example.com")).to_be_visible()

    # Now trigger an HTMX request to Org A's path while currentSelectedOrgId is Org B
    page.evaluate(
        "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
        f"/ui/orgs/{org_a_id}/domains",
    )
    page.wait_for_timeout(400)

    # In unpatched app.js, htmx:configRequest stamps X-Origin-Org-Id = org_b_id,
    # and htmx:beforeSwap uses reqOrgHeader (org_b_id) which matches currentSelectedOrgId,
    # allowing Org A's confidential domain to swap into Org B's content area!
    # Expected: Org A's secret domain must NOT be visible; Org B remains visible.
    expect(page.locator("text=alpha-secret.example.com")).not_to_be_visible()
    expect(page.locator("text=beta-public.example.com")).to_be_visible()


def test_g2_2_action_continuation_delayed_response_after_org_switch_browser(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """G2.2: Delayed action response must not trigger a GET or DOM update after switching orgs."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-0000000000a2"),
            email="g2-action-switch@example.com",
        )
        org_a = Organization(name="Tenant Alpha G22")
        org_b = Organization(name="Tenant Beta G22")
        session.add_all([user, org_a, org_b])
        session.flush()

        session.add(Membership(org_id=org_a.id, user_id=user.id, role="owner"))
        session.add(Membership(org_id=org_b.id, user_id=user.id, role="owner"))

        domain_a = Domain(
            org_id=org_a.id,
            name="alpha-action.example.com",
            verification_status="verified",
            verification_token="tok-a2",
        )
        domain_b = Domain(
            org_id=org_b.id,
            name="beta-action.example.com",
            verification_status="verified",
            verification_token="tok-b2",
        )
        session.add_all([domain_a, domain_b])
        session.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id
        domain_a_id = domain_a.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    expect(page.locator("#org-switcher-select option")).to_have_count(2)
    page.select_option("#org-switcher-select", str(org_a_id))
    expect(page.locator("text=alpha-action.example.com")).to_be_visible()

    # Navigate to domain A detail, then scans list
    page.locator(".btn-view-domain").click()
    expect(page.locator("h2.panel-title:has-text('alpha-action.example.com')")).to_be_visible()
    page.locator("#btn-view-scans").click()
    expect(page.locator("#btn-run-scan")).to_be_visible()

    # Intercept the action POST /orgs/{org_a_id}/domains/{domain_a_id}/scans
    held_scans: list[Route] = []
    page.route(
        re.compile(rf".*/orgs/{org_a_id}/domains/{domain_a_id}/scans.*"),
        lambda route: held_scans.append(route),
    )

    # Click run scan in Org A
    page.locator("#btn-run-scan").click()
    page.wait_for_timeout(200)
    assert len(held_scans) == 1, "Expected run-scan POST to be held"

    # Switch to Org B while action is in flight
    page.select_option("#org-switcher-select", str(org_b_id))
    expect(page.locator("text=beta-action.example.com")).to_be_visible()

    # Track any outgoing GET requests to Org A paths
    org_a_get_requests: list[str] = []
    page.on(
        "request",
        lambda req: (
            org_a_get_requests.append(req.url)
            if f"/ui/orgs/{org_a_id}/" in req.url
            else None
        ),
    )

    # Release the held action response
    held = held_scans.pop(0)
    held.continue_()
    page.wait_for_timeout(400)

    # The action continuation must NOT trigger loadScanDetail(org_a_id, ...) in Org B
    assert len(org_a_get_requests) == 0, (
        f"Expected no Org A GET requests, but got: {org_a_get_requests}"
    )
    # Org B domains list must still be visible and not swapped with Org A scan detail
    expect(page.locator("text=beta-action.example.com")).to_be_visible()
    expect(page.locator("#scan-detail-container")).not_to_be_attached()


def test_g2_2_action_continuation_delayed_response_after_logout_browser(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """G2.2: Delayed action response must not trigger a GET or DOM update after logout."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-0000000000a3"),
            email="g2-action-logout@example.com",
        )
        org = Organization(name="Logout Action Org")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="logout-action.example.com",
            verification_status="verified",
            verification_token="tok-l2",
        )
        session.add(domain)
        session.commit()
        org_id = org.id
        domain_id = domain.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    page.locator(".btn-view-domain").click()
    expect(page.locator("h2.panel-title:has-text('logout-action.example.com')")).to_be_visible()
    page.locator("#btn-view-scans").click()
    expect(page.locator("#btn-run-scan")).to_be_visible()

    # Intercept action POST
    held_scans: list[Route] = []
    page.route(
        re.compile(rf".*/orgs/{org_id}/domains/{domain_id}/scans.*"),
        lambda route: held_scans.append(route),
    )

    page.locator("#btn-run-scan").click()
    page.wait_for_timeout(200)
    assert len(held_scans) == 1

    # User logs out
    page.locator("#signout-button").click()
    expect(page.locator("#auth-section")).to_be_visible()
    expect(page.locator("#app-shell")).to_be_hidden()

    # Track any outgoing GET requests to /ui/orgs/
    post_logout_gets: list[str] = []
    page.on(
        "request",
        lambda req: (
            post_logout_gets.append(req.url)
            if "/ui/orgs/" in req.url
            else None
        ),
    )

    # Release held action response
    held = held_scans.pop(0)
    held.continue_()
    page.wait_for_timeout(400)

    # Must NOT have made any subsequent GET requests after logout
    assert len(post_logout_gets) == 0, (
        f"Expected no GET requests after logout, got: {post_logout_gets}"
    )
    expect(page.locator("#app-shell")).to_be_hidden()


def test_g2_3_load_org_switcher_delayed_after_logout_browser(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """G2.3: loadOrgSwitcher must not populate DOM or call loadDomainsList after logout."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-0000000000a4"),
            email="g2-switcher-logout@example.com",
        )
        org = Organization(name="Switcher Logout Org")
        session.add_all([user, org])
        session.flush()

        session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="switcher-logout.example.com",
            verification_status="verified",
            verification_token="tok-sw",
        )
        session.add(domain)
        session.commit()

    make_fake_jwt(user)

    # Hold GET /orgs when requested
    held_orgs: list[Route] = []
    holding_orgs = True

    def _hold_orgs(route: Route):
        nonlocal holding_orgs
        if holding_orgs and "/orgs" in route.request.url and route.request.method == "GET":
            holding_orgs = False
            held_orgs.append(route)
        else:
            route.fallback()

    page.route(re.compile(r".*/orgs$"), _hold_orgs)

    page.goto(f"{live_server}/app")
    page.locator("#signin-email").fill(user.email)
    page.locator("#signin-password").fill("ValidPassword123!")
    page.locator('#signin-form button[type="submit"]').click()
    page.locator("#app-shell").wait_for(state="visible")
    page.wait_for_timeout(200)

    assert len(held_orgs) == 1, "Expected GET /orgs to be held"

    # Now sign out while loadOrgSwitcher is awaiting GET /orgs
    page.locator("#signout-button").click()
    expect(page.locator("#auth-section")).to_be_visible()
    expect(page.locator("#app-shell")).to_be_hidden()

    # Track if loadDomainsList gets called after logout
    post_logout_domain_gets: list[str] = []
    page.on(
        "request",
        lambda req: (
            post_logout_domain_gets.append(req.url)
            if "/ui/orgs/" in req.url
            else None
        ),
    )

    # Release held GET /orgs
    held = held_orgs.pop(0)
    held.continue_()
    page.wait_for_timeout(400)

    # In unpatched app.js, loadOrgSwitcher continues, populates #org-switcher-select,
    # sets currentSelectedOrgId, and triggers loadDomainsList!
    # Expected: No domain GET requests, and org switcher must not have options
    assert len(post_logout_domain_gets) == 0, (
        f"Expected no domain GET requests after logout, got: {post_logout_domain_gets}"
    )
    expect(page.locator("#org-switcher-select option")).to_have_count(0)
    expect(page.locator("#app-shell")).to_be_hidden()


def test_g2_3_401_refresh_retry_delayed_after_org_switch_browser(
    page: Page,
    live_server: str,
    browser_session_factory: sessionmaker[Session],
) -> None:
    """G2.3: 401 refresh/retry must not re-issue requests for old org after switching orgs."""
    with browser_session_factory() as session:
        user = User(
            id=UUID("00000000-0000-0000-0000-0000000000a5"),
            email="g2-refresh-switch@example.com",
        )
        org_a = Organization(name="Tenant Alpha G23")
        org_b = Organization(name="Tenant Beta G23")
        session.add_all([user, org_a, org_b])
        session.flush()

        session.add(Membership(org_id=org_a.id, user_id=user.id, role="owner"))
        session.add(Membership(org_id=org_b.id, user_id=user.id, role="owner"))

        domain_a = Domain(
            org_id=org_a.id,
            name="alpha-refresh.example.com",
            verification_status="verified",
            verification_token="tok-ref-a",
        )
        domain_b = Domain(
            org_id=org_b.id,
            name="beta-refresh.example.com",
            verification_status="verified",
            verification_token="tok-ref-b",
        )
        session.add_all([domain_a, domain_b])
        session.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id

    make_fake_jwt(user)
    sign_in(page, user.email, live_server)

    expect(page.locator("#org-switcher-select option")).to_have_count(2)
    page.select_option("#org-switcher-select", str(org_a_id))
    expect(page.locator("text=alpha-refresh.example.com")).to_be_visible()

    # Intercept token refresh and hold it
    held_refresh: list[Route] = []
    page.route(
        re.compile(r".*/auth/v1/token\?grant_type=refresh_token.*"),
        lambda route: held_refresh.append(route),
    )

    should_401 = True

    def _route_domains(route: Route):
        if should_401:
            route.fulfill(
                status=401,
                content_type="application/json",
                body='{"detail": "Token expired"}',
            )
        else:
            route.fallback()

    page.route(re.compile(rf".*/ui/orgs/{org_a_id}/domains.*"), _route_domains)

    # Trigger an HTMX request on Org A that receives 401
    page.evaluate(
        "(path) => { window.htmx.ajax('GET', path, '#main-content-area'); }",
        f"/ui/orgs/{org_a_id}/domains",
    )

    page.wait_for_timeout(300)
    assert len(held_refresh) == 1, "Expected refreshSession to be in flight and held"
    should_401 = False

    # While refreshSession is in flight, user switches to Org B
    page.select_option("#org-switcher-select", str(org_b_id))
    expect(page.locator("text=beta-refresh.example.com")).to_be_visible()

    # Track retried requests to Org A after switching to Org B
    post_switch_org_a_retries: list[str] = []
    page.on(
        "request",
        lambda req: (
            post_switch_org_a_retries.append(req.url)
            if f"/ui/orgs/{org_a_id}/" in req.url
            else None
        ),
    )

    # Release held refresh response with valid session
    held = held_refresh.pop(0)
    fake_token = make_fake_jwt(user)
    held.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(
            {
                "access_token": fake_token,
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": f"ref_{fake_token}",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "aud": "authenticated",
                    "role": "authenticated",
                },
            }
        ),
    )
    page.wait_for_timeout(400)

    # In unpatched app.js, htmx:responseError retries window.htmx.ajax for Org A
    # while Org B is active!
    # Expected: No retry for Org A after switching to Org B, and Org B stays visible
    assert len(post_switch_org_a_retries) == 0, (
        f"Expected no Org A retry after switching to Org B, got: {post_switch_org_a_retries}"
    )
    expect(page.locator("text=beta-refresh.example.com")).to_be_visible()

