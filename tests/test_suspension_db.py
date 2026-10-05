"""v3.6c B-4: account suspension (403 per request, D4 schedule/scan stopping, D5 audit)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.admin import main as admin_main
from asm.admin import suspend_user, unsuspend_user
from asm.api import deps
from asm.api.deps import get_current_auth_settings, get_current_user
from asm.api.main import app
from asm.auth.config import AuthSettings
from asm.db.models import AuditEvent, Domain, Membership, Organization, ScanRun, ScanStage, User

pytestmark = pytest.mark.db

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
REASON = "Scanned third-party targets - ticket OPS-4471"


@pytest.fixture
def real_auth(lifecycle_client, lifecycle_org, monkeypatch):
    """lifecycle_client, but authenticated through the real get_current_user path.

    Only the JWT signature check is stubbed: the user row is upserted and read from
    PostgreSQL on every request exactly as in production.
    """
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_current_auth_settings] = lambda: AuthSettings(
        supabase_url="https://unit.supabase.co"
    )
    monkeypatch.setattr(
        deps,
        "verify_access_token",
        lambda **kwargs: {"user_id": TEST_USER_ID, "email": "testuser@example.com"},
    )
    return lifecycle_client, lifecycle_org


def _auth():
    return {"Authorization": "Bearer stub-token"}


def test_suspension_applies_on_the_very_next_request(real_auth, db_engine):
    client, org = real_auth
    assert client.get("/orgs", headers=_auth()).status_code == 200

    with Session(db_engine) as session:
        assert suspend_user(session, str(TEST_USER_ID), REASON) == 0

    for path in ("/orgs", f"/orgs/{org.id}/domains", f"/ui/orgs/{org.id}/domains"):
        resp = client.get(path, headers=_auth())
        assert resp.status_code == 403, path
        assert resp.json() == {"detail": "Account suspended"}, path
        assert "OPS-4471" not in resp.text

    with Session(db_engine) as session:
        assert unsuspend_user(session, str(TEST_USER_ID), "Appeal accepted") == 0
    assert client.get("/orgs", headers=_auth()).status_code == 200


def test_suspended_user_cannot_create_orgs_or_accept_invites(real_auth, db_engine):
    client, _ = real_auth
    with Session(db_engine) as session:
        suspend_user(session, str(TEST_USER_ID), REASON)
    assert client.post("/orgs", json={"name": "X"}, headers=_auth()).status_code == 403
    resp = client.post(
        "/invites/accept", json={"token": "x" * 43}, headers=_auth()
    )
    assert resp.status_code == 403


def _org_with_scans(session: Session, name: str, owners: list[User]) -> tuple[int, int, int]:
    org = Organization(name=name)
    session.add(org)
    session.flush()
    for owner in owners:
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
    domain = Domain(
        org_id=org.id,
        name=f"{name.lower().replace(' ', '-')}.example.com",
        verification_status="verified",
        scan_interval_hours=24,
        next_scan_at=datetime.now(UTC) + timedelta(hours=1),
    )
    session.add(domain)
    session.flush()
    queued = ScanRun(domain_id=domain.id, status="queued", trigger="scheduled")
    running = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    session.add_all([queued, running])
    session.flush()
    session.add(ScanStage(scan_run_id=queued.id, stage="discover", status="pending"))
    session.commit()
    return org.id, domain.id, queued.id


def test_d4_scanning_stops_only_where_every_owner_is_suspended(db_engine, clean_db):
    with Session(db_engine) as session:
        alice = User(id=uuid.uuid4(), email="alice@example.com")
        bob = User(id=uuid.uuid4(), email="bob@example.com")
        session.add_all([alice, bob])
        session.commit()
        solo_org, solo_domain, solo_queued = _org_with_scans(session, "Solo Org", [alice])
        shared_org, shared_domain, shared_queued = _org_with_scans(
            session, "Shared Org", [alice, bob]
        )
        alice_id = alice.id

    with Session(db_engine) as session:
        assert suspend_user(session, str(alice_id), REASON) == 0

    with Session(db_engine) as session:
        solo = session.get(Domain, solo_domain)
        assert solo.scan_interval_hours is None and solo.next_scan_at is None
        cancelled = session.get(ScanRun, solo_queued)
        assert cancelled.status == "failed"
        assert "suspended" in cancelled.error
        stage = session.scalar(select(ScanStage).where(ScanStage.scan_run_id == solo_queued))
        assert stage.status == "skipped"

        shared = session.get(Domain, shared_domain)
        assert shared.scan_interval_hours == 24  # bob is still an active owner
        assert session.get(ScanRun, shared_queued).status == "queued"

        events = {
            e.org_id: e
            for e in session.scalars(
                select(AuditEvent).where(AuditEvent.action == "account.suspended")
            )
        }
        assert set(events) == {solo_org, shared_org}  # D5: one event per org
        assert events[solo_org].metadata_ == {
            "user_id": str(alice_id),
            "schedules_cancelled": 1,
            "queued_scans_cancelled": 1,
        }
        assert events[shared_org].metadata_["schedules_cancelled"] == 0
        assert events[solo_org].actor_type == "operator"
        assert events[solo_org].target_type == "user"
        for event in events.values():
            assert "OPS-4471" not in str(event.metadata_)

        user = session.get(User, alice_id)
        assert user.suspended_reason == REASON  # stored for the operator only


def test_unsuspend_restores_access_but_not_schedules(db_engine, clean_db):
    with Session(db_engine) as session:
        carol = User(id=uuid.uuid4(), email="carol@example.com")
        session.add(carol)
        session.commit()
        org_id, domain_id, _ = _org_with_scans(session, "Carol Org", [carol])
        carol_id = carol.id

    with Session(db_engine) as session:
        suspend_user(session, str(carol_id), REASON)
    with Session(db_engine) as session:
        assert unsuspend_user(session, str(carol_id), "Appeal accepted") == 0

    with Session(db_engine) as session:
        user = session.get(User, carol_id)
        assert user.suspended_at is None and user.suspended_reason is None
        assert session.get(Domain, domain_id).scan_interval_hours is None  # stays off
        actions = session.scalars(
            select(AuditEvent.action).where(AuditEvent.org_id == org_id).order_by(AuditEvent.id)
        ).all()
        assert actions[-2:] == ["account.suspended", "account.unsuspended"]


def test_reason_never_reaches_tenant_audit_api(real_auth, db_engine):
    client, org = real_auth
    with Session(db_engine) as session:
        bob = User(id=uuid.uuid4(), email="bob2@example.com")
        session.add(bob)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=bob.id, role="viewer"))
        session.commit()
        suspend_user(session, str(bob.id), REASON)

    resp = client.get(f"/orgs/{org.id}/audit-events", headers=_auth())
    assert resp.status_code == 200
    assert "account.suspended" in resp.text
    assert "OPS-4471" not in resp.text
    ui = client.get(f"/ui/orgs/{org.id}/audit-events", headers=_auth())
    assert ui.status_code == 200
    assert "OPS-4471" not in ui.text


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["suspend-user", "--user-id", str(TEST_USER_ID), "--reason", "   "], "--reason"),
        (["suspend-user", "--user-id", "not-a-uuid", "--reason", "x"], "not a valid user ID"),
        (["suspend-user", "--user-id", str(uuid.uuid4()), "--reason", "x"], "does not exist"),
        (["unsuspend-user", "--user-id", str(TEST_USER_ID), "--reason", "x"], "not suspended"),
    ],
)
def test_cli_rejects_bad_input(lifecycle_org, db_engine, capsys, argv, message):
    with Session(db_engine) as session:
        assert admin_main(argv, session=session) == 1
    assert message in capsys.readouterr().err


def test_cli_refuses_double_suspension(lifecycle_org, db_engine, capsys):
    argv = ["suspend-user", "--user-id", str(TEST_USER_ID), "--reason", REASON]
    with Session(db_engine) as session:
        assert admin_main(argv, session=session) == 0
    with Session(db_engine) as session:
        assert admin_main(argv, session=session) == 1
    assert "already suspended" in capsys.readouterr().err


def test_asm_admin_cli_suspends_and_unsuspends(lifecycle_org, db_engine, monkeypatch, capsys):
    """`asm admin suspend-user` / `unsuspend-user` (the installed entry point) work end to end."""
    from sqlalchemy.orm import sessionmaker

    from asm.cli import main as cli_main

    monkeypatch.setattr(
        "asm.db.session.get_session_factory", lambda: sessionmaker(bind=db_engine)
    )
    uid = str(TEST_USER_ID)
    assert cli_main(["admin", "suspend-user", "--user-id", uid, "--reason", REASON]) == 0
    with Session(db_engine) as session:
        assert session.get(User, TEST_USER_ID).suspended_at is not None
    assert cli_main(["admin", "unsuspend-user", "--user-id", uid, "--reason", "ok"]) == 0
    with Session(db_engine) as session:
        assert session.get(User, TEST_USER_ID).suspended_at is None
    assert "re-enable" in capsys.readouterr().out
