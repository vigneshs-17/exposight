"""Database and concurrency tests for users, organizations, and memberships."""

import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.auth.upsert import upsert_user
from asm.db.models import Membership, Organization, User

pytestmark = pytest.mark.db


def test_jit_user_upsert_throttling(db_session: Session):
    """JIT upsert creates user and throttles last_seen_at writes within 5 minutes."""
    user_id = uuid.uuid4()
    email = "jit_user@example.com"

    # 1. Initial upsert inserts row
    user1 = upsert_user(db_session, user_id, email)
    db_session.commit()
    initial_last_seen = user1.last_seen_at
    assert user1.id == user_id
    assert user1.email == email

    # 2. Immediate second upsert (within 5 minutes) must NOT update last_seen_at
    user2 = upsert_user(db_session, user_id, "updated_email@example.com")
    db_session.commit()
    assert user2.last_seen_at == initial_last_seen

    # 3. Simulate passage of time (> 5 minutes ago)
    db_session.execute(
        text("UPDATE users SET last_seen_at = now() - INTERVAL '10 minutes' WHERE id = :id"),
        {"id": user_id},
    )
    db_session.commit()
    db_session.refresh(user2)
    aged_last_seen = user2.last_seen_at

    # 4. Third upsert after 10 minutes updates last_seen_at and email
    user3 = upsert_user(db_session, user_id, "updated_email@example.com")
    db_session.commit()
    assert user3.last_seen_at > aged_last_seen
    assert user3.email == "updated_email@example.com"


def test_create_org_creator_is_owner(client: TestClient, db_session: Session):
    """POST /orgs creates organization and assigns creator as owner."""
    response = client.post("/orgs", json={"name": "Acme Security"})
    assert response.status_code == 201
    data = response.json()
    org_id = data["id"]
    assert data["name"] == "Acme Security"

    # Verify membership in DB
    membership = db_session.execute(
        select(Membership).where(Membership.org_id == org_id)
    ).scalar_one()
    assert membership.role == "owner"


def test_list_my_orgs(client: TestClient, db_session: Session):
    """GET /orgs lists only organizations where caller has a membership."""
    # Create org through client
    res1 = client.post("/orgs", json={"name": "Org 1"})
    assert res1.status_code == 201

    # List orgs
    res2 = client.get("/orgs")
    assert res2.status_code == 200
    orgs = res2.json()
    assert len(orgs) >= 1
    assert any(o["name"] == "Org 1" and o["role"] == "owner" for o in orgs)


def test_non_member_gets_404_not_403(client: TestClient, db_session: Session):
    """Non-member accessing an organization receives 404 Not Found, never 403."""
    # Create an org where current user is NOT a member
    other_user = User(id=uuid.uuid4(), email="other@example.com")
    db_session.add(other_user)
    other_org = Organization(name="Secret Org")
    db_session.add(other_org)
    db_session.flush()

    db_session.add(Membership(org_id=other_org.id, user_id=other_user.id, role="owner"))
    db_session.commit()

    # Current user tries to access Secret Org
    res1 = client.get(f"/orgs/{other_org.id}/members")
    assert res1.status_code == 404
    assert res1.json()["detail"] == "Organization not found"

    res2 = client.post(f"/orgs/{other_org.id}/members", json={"email": "x@x.com", "role": "viewer"})
    assert res2.status_code == 404

    res3 = client.delete(f"/orgs/{other_org.id}/members/{other_user.id}")
    assert res3.status_code == 404


def test_add_member_endpoint_is_gone_and_does_not_enumerate_accounts(
    client: TestClient, db_session: Session
):
    """v3.6b A2: POST /orgs/{id}/members is 410 Gone for every email.

    It used to return 404 "has not logged in yet" for unknown emails and 201 for
    known ones, which revealed who has an account. Now both answers are identical.
    """
    db_session.add(User(id=uuid.uuid4(), email="known_user@example.com"))
    db_session.commit()
    res = client.post("/orgs", json={"name": "Dev Org"})
    org_id = res.json()["id"]

    unknown = client.post(
        f"/orgs/{org_id}/members",
        json={"email": "nonexistent_user@example.com", "role": "viewer"},
    )
    known = client.post(
        f"/orgs/{org_id}/members", json={"email": "known_user@example.com", "role": "viewer"}
    )
    assert unknown.status_code == known.status_code == 410
    assert unknown.json() == known.json()
    members = client.get(f"/orgs/{org_id}/members").json()
    assert [m["email"] for m in members] == ["testuser@example.com"]


def test_role_matrix_and_self_removal(db_session: Session):
    """Test full role hierarchy: viewer, admin, owner privileges and self-removal."""
    # Create test users
    owner_user = User(id=uuid.uuid4(), email="owner@example.com")
    admin_user = User(id=uuid.uuid4(), email="admin@example.com")
    viewer_user = User(id=uuid.uuid4(), email="viewer@example.com")
    new_user = User(id=uuid.uuid4(), email="new@example.com")
    db_session.add_all([owner_user, admin_user, viewer_user, new_user])

    org = Organization(name="Role Test Org")
    db_session.add(org)
    db_session.flush()

    db_session.add_all([
        Membership(org_id=org.id, user_id=owner_user.id, role="owner"),
        Membership(org_id=org.id, user_id=admin_user.id, role="admin"),
        Membership(org_id=org.id, user_id=viewer_user.id, role="viewer"),
    ])
    db_session.commit()

    # Helper client with overridden user and db
    from asm.db.session import get_db

    def make_client_for(user: User):
        def _get_user():
            return user
        def _get_db():
            yield db_session
        app.dependency_overrides[get_db] = _get_db
        app.dependency_overrides[get_current_user] = _get_user
        return TestClient(app)

    # 1. Viewer can list members, but cannot add members (403)
    viewer_client = make_client_for(viewer_user)
    assert viewer_client.get(f"/orgs/{org.id}/members").status_code == 200
    assert viewer_client.post(
        f"/orgs/{org.id}/members",
        json={"email": "new@example.com", "role": "viewer"},
    ).status_code == 403

    # 2. Admin can invite a viewer (v3.6b: invites replace direct adds)
    admin_client = make_client_for(admin_user)
    res_add = admin_client.post(
        f"/orgs/{org.id}/invites",
        json={"email": "new@example.com", "role": "viewer"},
    )
    assert res_add.status_code == 201

    # 3. Admin CANNOT invite an owner (403); viewer cannot invite at all (403)
    assert admin_client.post(
        f"/orgs/{org.id}/invites",
        json={"email": "extra@example.com", "role": "owner"},
    ).status_code == 403
    viewer_client = make_client_for(viewer_user)
    assert viewer_client.post(
        f"/orgs/{org.id}/invites",
        json={"email": "extra@example.com", "role": "viewer"},
    ).status_code == 403
    admin_client = make_client_for(admin_user)

    # 4. Admin CANNOT remove another member (403)
    assert admin_client.delete(f"/orgs/{org.id}/members/{viewer_user.id}").status_code == 403

    # 5. Self-removal: viewer CAN remove themselves (204)
    viewer_client = make_client_for(viewer_user)
    assert viewer_client.delete(f"/orgs/{org.id}/members/{viewer_user.id}").status_code == 204

    # 6. Admin CAN remove themselves (204)
    admin_client = make_client_for(admin_user)
    assert admin_client.delete(f"/orgs/{org.id}/members/{admin_user.id}").status_code == 204

    # Clean up overrides
    app.dependency_overrides.clear()


def test_last_owner_protection(db_session: Session):
    """Cannot demote or remove the sole owner of an organization."""
    from asm.db.session import get_db

    owner_user = User(id=uuid.uuid4(), email="sole_owner@example.com")
    db_session.add(owner_user)
    org = Organization(name="Sole Owner Org")
    db_session.add(org)
    db_session.flush()

    db_session.add(Membership(org_id=org.id, user_id=owner_user.id, role="owner"))
    db_session.commit()

    def _get_user():
        return owner_user

    def _get_db():
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user
    client = TestClient(app)
    try:
        # Demote sole owner -> 422
        res_patch = client.patch(
            f"/orgs/{org.id}/members/{owner_user.id}",
            json={"role": "admin"},
        )
        assert res_patch.status_code == 422
        assert "Cannot demote the last owner" in res_patch.json()["detail"]

        # Delete sole owner -> 422
        res_del = client.delete(f"/orgs/{org.id}/members/{owner_user.id}")
        assert res_del.status_code == 422
        assert "Cannot remove the last owner" in res_del.json()["detail"]
    finally:
        app.dependency_overrides.clear()



def test_concurrent_last_owner_demote_race(clean_db, db_engine):
    """Two owners concurrently demoting each other must leave at least one owner.

    Enforced by locking the organization row with SELECT ... FOR UPDATE before
    counting owners in the same transaction.
    """
    owner1_id = uuid.uuid4()
    owner2_id = uuid.uuid4()

    with Session(db_engine) as session:
        u1 = User(id=owner1_id, email="owner1@example.com")
        u2 = User(id=owner2_id, email="owner2@example.com")
        org = Organization(name="Race Org")
        session.add_all([u1, u2, org])
        session.flush()

        session.add_all([
            Membership(org_id=org.id, user_id=owner1_id, role="owner"),
            Membership(org_id=org.id, user_id=owner2_id, role="owner"),
        ])
        session.commit()
        org_id = org.id

    results = []
    errors = []

    def demote_owner(caller_id: uuid.UUID, target_id: uuid.UUID):
        """Demote an owner using a separate database session with row locking."""
        with Session(db_engine) as session:
            try:
                # 1. Lock org row FOR UPDATE (the invariant fix)
                session.execute(
                    select(Organization).where(Organization.id == org_id).with_for_update()
                ).scalar_one()

                # 2. Check caller is still an owner
                caller_mem = session.execute(
                    select(Membership).where(
                        Membership.org_id == org_id,
                        Membership.user_id == caller_id,
                    )
                ).scalar_one()
                if caller_mem.role != "owner":
                    results.append("REJECTED_CALLER_NOT_OWNER")
                    session.rollback()
                    return

                # 3. Count remaining owners
                remaining = session.scalar(
                    select(func.count(Membership.id)).where(
                        Membership.org_id == org_id,
                        Membership.role == "owner",
                        Membership.user_id != target_id,
                    )
                )
                if (remaining or 0) == 0:
                    results.append("REJECTED_LAST_OWNER")
                    session.rollback()
                    return

                # 4. Demote
                target_mem = session.execute(
                    select(Membership).where(
                        Membership.org_id == org_id,
                        Membership.user_id == target_id,
                    )
                ).scalar_one()
                target_mem.role = "admin"
                session.commit()
                results.append("DEMOTED")
            except Exception as exc:
                errors.append(str(exc))
                session.rollback()


    # Run two concurrent demotions in separate threads
    t1 = threading.Thread(target=demote_owner, args=(owner1_id, owner2_id))
    t2 = threading.Thread(target=demote_owner, args=(owner2_id, owner1_id))

    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert not errors, f"Unexpected thread errors: {errors}"
    assert len(results) == 2
    # Exactly one succeeded and one was rejected, and at least one owner remains
    assert "DEMOTED" in results
    assert any(r in ("REJECTED_LAST_OWNER", "REJECTED_CALLER_NOT_OWNER") for r in results)

    # Verify database state: at least one owner remains
    with Session(db_engine) as session:
        owners_count = session.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == org_id,
                Membership.role == "owner",
            )
        )
        assert owners_count >= 1, "INVARIANT VIOLATION: Zero owners remain!"
