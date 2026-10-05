"""v3.6b A2: single-use, email-bound organization invites replace adding members by email."""

import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.auth.upsert import upsert_user
from asm.db.models import AuditEvent, Membership, Organization, OrgInvite, User
from asm.db.session import get_db

pytestmark = pytest.mark.db


@pytest.fixture
def org_id(client: TestClient) -> int:
    """An org owned by the conftest client user (testuser@example.com)."""
    return client.post("/orgs", json={"name": "Invite Org"}).json()["id"]


def _invite(client: TestClient, org_id: int, email: str, role: str = "viewer"):
    return client.post(f"/orgs/{org_id}/invites", json={"email": email, "role": role})


def _accept_as(client: TestClient, user: User, token: str):
    """POST /invites/accept as another user, then restore the client's own identity."""
    previous = app.dependency_overrides[get_current_user]
    app.dependency_overrides[get_current_user] = lambda: user
    try:
        return client.post("/invites/accept", json={"token": token})
    finally:
        app.dependency_overrides[get_current_user] = previous


def _user(db_session: Session, email: str) -> User:
    user = User(id=uuid.uuid4(), email=email)
    db_session.add(user)
    db_session.commit()
    return user


def test_create_invite_returns_token_once_and_stores_only_its_hash(
    client, db_session, org_id
):
    resp = _invite(client, org_id, "New.Person@Example.com")
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "new.person@example.com"
    assert len(body["token"]) >= 40

    row = db_session.get(OrgInvite, body["id"])
    assert row.token_hash == hashlib.sha256(body["token"].encode()).hexdigest()
    assert body["token"] not in row.token_hash

    listed = client.get(f"/orgs/{org_id}/invites").json()
    assert [i["id"] for i in listed] == [body["id"]]
    assert "token" not in listed[0]


def test_invite_response_is_identical_for_existing_and_unknown_accounts(
    client, db_session, org_id
):
    """No account enumeration: users are never looked up by email."""
    _user(db_session, "has-account@example.com")
    known = _invite(client, org_id, "has-account@example.com")
    unknown = _invite(client, org_id, "no-account@example.com")
    assert known.status_code == unknown.status_code == 201
    assert set(known.json()) == set(unknown.json())
    members = client.get(f"/orgs/{org_id}/members").json()
    assert len(members) == 1  # nobody was added without consent


def test_accept_creates_membership_and_token_is_single_use(client, db_session, org_id):
    invitee = _user(db_session, "invitee@example.com")
    token = _invite(client, org_id, "INVITEE@example.com", role="admin").json()["token"]

    first = _accept_as(client, invitee, token)
    assert first.status_code == 200, first.text
    assert first.json()["role"] == "admin"
    membership = db_session.scalar(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == invitee.id)
    )
    assert membership.role == "admin"

    again = _accept_as(client, invitee, token)
    assert again.status_code == 404


def test_accept_with_different_email_is_refused(client, db_session, org_id):
    intruder = _user(db_session, "intruder@example.com")
    token = _invite(client, org_id, "victim@example.com").json()["token"]

    resp = _accept_as(client, intruder, token)
    assert resp.status_code == 403
    assert "victim" not in resp.text
    assert db_session.scalar(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == intruder.id)
    ) is None


def test_accept_refused_for_user_without_email(client, db_session, org_id):
    no_email = _user(db_session, "")
    token = _invite(client, org_id, "someone@example.com").json()["token"]
    assert _accept_as(client, no_email, token).status_code == 403


@pytest.mark.parametrize("token", ["x" * 43, "not-a-real-token-but-long-enough"])
def test_unknown_token_is_404(client, db_session, org_id, token):
    user = _user(db_session, "someone@example.com")
    resp = _accept_as(client, user, token)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Invite not found or no longer valid"


def test_expired_invite_cannot_be_accepted_or_listed(client, db_session, org_id):
    invitee = _user(db_session, "late@example.com")
    body = _invite(client, org_id, "late@example.com").json()
    row = db_session.get(OrgInvite, body["id"])
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    assert _accept_as(client, invitee, body["token"]).status_code == 404
    assert client.get(f"/orgs/{org_id}/invites").json() == []


def test_revoked_invite_cannot_be_accepted(client, db_session, org_id):
    invitee = _user(db_session, "revoked@example.com")
    body = _invite(client, org_id, "revoked@example.com").json()

    assert client.delete(f"/orgs/{org_id}/invites/{body['id']}").status_code == 204
    assert client.delete(f"/orgs/{org_id}/invites/{body['id']}").status_code == 409
    assert _accept_as(client, invitee, body["token"]).status_code == 404
    assert client.get(f"/orgs/{org_id}/invites").json() == []


def test_existing_member_gets_409_and_invite_stays_unused(client, db_session, org_id):
    me = db_session.get(User, uuid.UUID("00000000-0000-0000-0000-000000000001"))
    body = _invite(client, org_id, me.email).json()
    resp = client.post("/invites/accept", json={"token": body["token"]})
    assert resp.status_code == 409
    assert db_session.get(OrgInvite, body["id"]).accepted_at is None


def test_only_owners_can_invite_owners(client, db_session, org_id):
    admin = _user(db_session, "admin2@example.com")
    db_session.add(Membership(org_id=org_id, user_id=admin.id, role="admin"))
    db_session.commit()

    assert _invite(client, org_id, "boss@example.com", role="owner").status_code == 201
    previous = app.dependency_overrides[get_current_user]
    app.dependency_overrides[get_current_user] = lambda: admin
    try:
        assert _invite(client, org_id, "boss2@example.com", role="owner").status_code == 403
        assert _invite(client, org_id, "staff@example.com", role="admin").status_code == 201
    finally:
        app.dependency_overrides[get_current_user] = previous


def test_invites_are_tenant_scoped(client, db_session, org_id):
    other_org = Organization(name="Other Org")
    db_session.add(other_org)
    db_session.commit()

    assert _invite(client, other_org.id, "x@example.com").status_code == 404
    assert client.get(f"/orgs/{other_org.id}/invites").status_code == 404

    mine = _invite(client, org_id, "y@example.com").json()
    foreign = OrgInvite(
        org_id=other_org.id,
        email="z@example.com",
        role="viewer",
        token_hash="0" * 64,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(foreign)
    db_session.commit()
    # Revoking another org's invite through my org id is 404, not a cross-tenant write.
    assert client.delete(f"/orgs/{org_id}/invites/{foreign.id}").status_code == 404
    assert client.delete(f"/orgs/{org_id}/invites/{mine['id']}").status_code == 204


def test_invite_audit_events_contain_no_email(client, db_session, org_id):
    body = _invite(client, org_id, "private.person@example.com").json()
    client.delete(f"/orgs/{org_id}/invites/{body['id']}")
    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == org_id, AuditEvent.action.like("invite.%")
        )
    ).all()
    assert {e.action for e in events} == {"invite.created", "invite.revoked"}
    for event in events:
        assert event.target_type == "invite"
        assert event.target_id == str(body["id"])
        assert "@" not in str(event.metadata_)


def test_changed_email_is_written_immediately_by_upsert(db_session):
    """Invite acceptance compares users.email, so a new email must not wait 5 minutes."""
    user_id = uuid.uuid4()
    upsert_user(db_session, user_id, "old@example.com")
    user = upsert_user(db_session, user_id, "new@example.com")
    assert user.email == "new@example.com"


def test_concurrent_accepts_use_the_token_once(clean_db, db_engine):
    """Two simultaneous accepts of one token: exactly one succeeds (row lock on the invite)."""
    with Session(db_engine) as session:
        owner = User(id=uuid.uuid4(), email="owner@example.com")
        invitee = User(id=uuid.uuid4(), email="race@example.com")
        org = Organization(name="Race Org")
        session.add_all([owner, invitee, org])
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        token = "race-token-" + uuid.uuid4().hex
        session.add(
            OrgInvite(
                org_id=org.id,
                email="race@example.com",
                role="viewer",
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        session.commit()
        org_id, invitee_id = org.id, invitee.id

    def _db():
        with Session(db_engine) as session:
            yield session

    def _user_override():
        with Session(db_engine) as session:
            return session.get(User, invitee_id)

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user_override
    statuses: list[int] = []
    barrier = threading.Barrier(2)

    def accept():
        with TestClient(app) as tc:
            barrier.wait()
            statuses.append(tc.post("/invites/accept", json={"token": token}).status_code)

    try:
        threads = [threading.Thread(target=accept) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
    finally:
        app.dependency_overrides.clear()

    assert sorted(statuses) == [200, 404]
    with Session(db_engine) as session:
        count = len(
            session.scalars(select(Membership).where(Membership.org_id == org_id)).all()
        )
    assert count == 2  # owner + invitee, never a duplicate
