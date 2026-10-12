"""H-Fix-1: an invited user who may not create orgs joins one from the dashboard form."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from playwright.sync_api import expect
from sqlalchemy.orm import Session, sessionmaker

from asm.api.deps import get_org_creation_allowlist
from asm.api.main import app
from asm.api.routes_orgs import hash_invite_token
from asm.db.models import Organization, OrgInvite, User
from tests.browser.helpers import sign_in

pytestmark = pytest.mark.browser

GUEST_EMAIL = "guest@example.com"


def _seed_guest_and_invite(factory: sessionmaker[Session]) -> str:
    """An org with a pending viewer invite for a guest who belongs to no org."""
    token = secrets.token_urlsafe(32)
    with factory() as session:
        guest = User(id=UUID("00000000-0000-0000-0000-000000000002"), email=GUEST_EMAIL)
        org = Organization(name="Invite Corp")
        session.add_all([guest, org])
        session.flush()
        session.add(
            OrgInvite(
                org_id=org.id,
                email=GUEST_EMAIL,
                role="viewer",
                token_hash=hash_invite_token(token),
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
        )
        session.commit()
    return token


def test_browser_unlisted_user_accepts_invite_and_sees_org(
    make_page, live_server: str, browser_session_factory: sessionmaker[Session]
) -> None:
    app.dependency_overrides[get_org_creation_allowlist] = lambda: frozenset()
    token = _seed_guest_and_invite(browser_session_factory)

    with make_page() as page:
        sign_in(page, GUEST_EMAIL, live_server)
        main = page.locator("#main-content-area")
        expect(main.locator("#no-org-invite-only")).to_be_visible()
        expect(main.locator("#create-org-form")).to_have_count(0)

        page.locator("#invite-token").fill(token)
        page.locator('#accept-invite-form button[type="submit"]').click()

        expect(main).to_contain_text("Domains for Invite Corp")
        expect(page.locator("#org-switcher-select")).to_contain_text("Invite Corp (viewer)")
        expect(page.locator("#global-error-box")).to_be_hidden()


def test_browser_invalid_invite_token_shows_error(
    make_page, live_server: str, browser_session_factory: sessionmaker[Session]
) -> None:
    app.dependency_overrides[get_org_creation_allowlist] = lambda: frozenset()
    _seed_guest_and_invite(browser_session_factory)

    with make_page(allowed_error_statuses=(404,)) as page:
        sign_in(page, GUEST_EMAIL, live_server)
        page.locator("#invite-token").fill(secrets.token_urlsafe(32))
        page.locator('#accept-invite-form button[type="submit"]').click()

        error_box = page.locator("#global-error-box")
        expect(error_box).to_be_visible()
        expect(error_box).to_have_text("Invite not found or no longer valid")
        expect(page.locator("#no-org-invite-only")).to_be_visible()
