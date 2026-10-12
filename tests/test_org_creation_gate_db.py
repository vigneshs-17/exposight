"""H-Auth-1: only accounts in ORG_CREATION_ALLOWED_EMAILS may create organizations."""

import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user, get_org_creation_allowlist
from asm.api.main import app
from asm.config import Settings
from asm.db.models import Organization, User

pytestmark = pytest.mark.db

CLIENT_EMAIL = "testuser@example.com"  # the conftest client user


def _allow(*emails: str) -> None:
    app.dependency_overrides[get_org_creation_allowlist] = lambda: frozenset(emails)


def _org_count(db_session: Session) -> int:
    return db_session.scalar(select(func.count(Organization.id))) or 0


def test_listed_user_can_create_org(client: TestClient) -> None:
    _allow(CLIENT_EMAIL)
    resp = client.post("/orgs", json={"name": "Allowed Org"})
    assert resp.status_code == 201, resp.text


def test_non_listed_user_gets_403(client: TestClient, db_session: Session) -> None:
    _allow("someone-else@example.com")
    before = _org_count(db_session)
    resp = client.post("/orgs", json={"name": "Stranger Org"})
    assert resp.status_code == 403
    assert "invite" in resp.json()["detail"]
    assert _org_count(db_session) == before


def test_empty_list_blocks_everyone(client: TestClient, db_session: Session) -> None:
    _allow()
    before = _org_count(db_session)
    assert client.post("/orgs", json={"name": "Nobody"}).status_code == 403
    assert _org_count(db_session) == before


def test_match_is_case_and_whitespace_insensitive(client: TestClient, db_session: Session) -> None:
    user = app.dependency_overrides[get_current_user]()
    user.email = "  TestUser@Example.COM "
    db_session.commit()
    _allow(CLIENT_EMAIL)
    assert client.post("/orgs", json={"name": "Case Org"}).status_code == 201


def test_non_listed_user_can_accept_invite_and_see_org(
    client: TestClient, db_session: Session
) -> None:
    _allow(CLIENT_EMAIL)
    org_id = client.post("/orgs", json={"name": "Invite Only Org"}).json()["id"]
    token = client.post(
        f"/orgs/{org_id}/invites", json={"email": "guest@example.com", "role": "viewer"}
    ).json()["token"]

    guest = User(id=uuid.uuid4(), email="guest@example.com")
    db_session.add(guest)
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: guest

    assert client.post("/orgs", json={"name": "Guest Org"}).status_code == 403
    accepted = client.post("/invites/accept", json={"token": token})
    assert accepted.status_code == 200, accepted.text
    assert [o["id"] for o in client.get("/orgs").json()] == [org_id]


def test_empty_org_view_hides_form_for_non_listed_user(client: TestClient) -> None:
    _allow()
    html = client.get("/ui/empty-org").text
    assert 'id="create-org-form"' not in html
    assert "invite-only" in html

    _allow(CLIENT_EMAIL)
    html = client.get("/ui/empty-org").text
    assert 'id="create-org-form"' in html


def test_setting_normalizes_and_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/x")
    monkeypatch.delenv("ORG_CREATION_ALLOWED_EMAILS", raising=False)
    assert Settings(_env_file=None).org_creation_allowed_emails == []
    monkeypatch.setenv("ORG_CREATION_ALLOWED_EMAILS", '[" Admin@Example.COM "]')
    assert Settings(_env_file=None).org_creation_allowed_emails == ["admin@example.com"]
    monkeypatch.setenv("ORG_CREATION_ALLOWED_EMAILS", '["not-an-email"]')
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
