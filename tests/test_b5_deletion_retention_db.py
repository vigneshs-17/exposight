"""v3.6c B-5: org tombstone delete, DELETE /me (D6), retention purge (D8, D9).

Every fixture here builds on db_session, which skips when TEST_DATABASE_URL is unset.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from asm.admin import main as admin_main
from asm.db.models import (
    AlertNotification,
    AuditEvent,
    Domain,
    Membership,
    Organization,
    OrgInvite,
    ScanChange,
    ScanRun,
    User,
)
from asm.retention import purge_expired

pytestmark = pytest.mark.db

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
NOW = datetime.now(UTC)
OLD = NOW - timedelta(days=200)


def _user(db: Session, email: str) -> User:
    user = User(id=uuid.uuid4(), email=email)
    db.add(user)
    db.flush()
    return user


def _org(db: Session, name: str, members: list[tuple[uuid.UUID, str]]) -> Organization:
    org = Organization(name=name)
    db.add(org)
    db.flush()
    for user_id, role in members:
        db.add(Membership(org_id=org.id, user_id=user_id, role=role))
    db.flush()
    return org


def _scan(db: Session, domain: Domain, status: str, created_at: datetime) -> ScanRun:
    run = ScanRun(domain_id=domain.id, status=status, created_at=created_at)
    db.add(run)
    db.flush()
    return run


def _change(db: Session, domain: Domain, run: ScanRun, baseline: ScanRun) -> ScanChange:
    change = ScanChange(
        domain_id=domain.id,
        scan_run_id=run.id,
        baseline_scan_run_id=baseline.id,
        change_type="PORT_OPENED",
        category="exposure",
        severity="HIGH",
        asset="a.example.com",
        evidence="portscan",
        observed_at=run.created_at,
    )
    db.add(change)
    db.flush()
    return change


def _notification(db: Session, domain: Domain, status: str, created_at: datetime):
    n = AlertNotification(
        domain_id=domain.id,
        recipient=f"{uuid.uuid4().hex[:8]}@example.com",
        subject="s",
        body="b",
        status=status,
        created_at=created_at,
    )
    db.add(n)
    db.flush()
    return n


def _invite(db: Session, org: Organization, email: str, **fields) -> OrgInvite:
    invite = OrgInvite(
        org_id=org.id,
        email=email,
        role="viewer",
        token_hash=uuid.uuid4().hex,
        expires_at=fields.pop("expires_at", NOW + timedelta(days=7)),
        **fields,
    )
    db.add(invite)
    db.flush()
    return invite


def _ids(db: Session, model, ids) -> set:
    db.expire_all()
    return set(db.scalars(select(model.id).where(model.id.in_(list(ids)))).all())


# --- DELETE /orgs/{org_id} -------------------------------------------------------------


@pytest.fixture
def populated_org(db_session: Session, test_org: Organization):
    """test_org with a domain, two scans, a change, a notification, a second member,
    an invite and a prior audit event; plus an unrelated org that must stay intact."""
    db = db_session
    other_member = _user(db, "member@example.com")
    db.add(Membership(org_id=test_org.id, user_id=other_member.id, role="viewer"))
    domain = Domain(org_id=test_org.id, name="tombstone.example.com")
    db.add(domain)
    db.flush()
    first = _scan(db, domain, "succeeded", NOW - timedelta(days=2))
    second = _scan(db, domain, "succeeded", NOW - timedelta(days=1))
    change = _change(db, domain, second, first)
    note = _notification(db, domain, "sent", NOW)
    invite = _invite(db, test_org, "invitee@example.com")
    db.add(
        AuditEvent(
            org_id=test_org.id,
            actor_type="user",
            actor_user_id=TEST_USER_ID,
            action="org.created",
            target_type="org",
            target_id=str(test_org.id),
        )
    )

    bystander = _org(db, "Bystander", [(other_member.id, "owner")])
    bystander_domain = Domain(org_id=bystander.id, name="keep.example.com")
    db.add(bystander_domain)
    db.flush()
    bystander_scan = _scan(db, bystander_domain, "succeeded", NOW)
    return {
        "org": test_org,
        "domain": domain,
        "scans": {first.id, second.id},
        "change": change.id,
        "note": note.id,
        "invite": invite.id,
        "bystander": bystander,
        "bystander_domain": bystander_domain.id,
        "bystander_scan": bystander_scan.id,
    }


def test_owner_delete_org_tombstones_it_and_removes_all_its_data(client, db_session, populated_org):
    db = db_session
    org_id = populated_org["org"].id
    audit_before = db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.org_id == org_id))

    resp = client.delete(f"/orgs/{org_id}")
    assert resp.status_code == 204

    db.expire_all()
    org = db.get(Organization, org_id)
    assert org is not None
    assert org.name == f"deleted-org-{org_id}"
    assert org.system_kind == "deleted"
    assert _ids(db, Domain, [populated_org["domain"].id]) == set()
    assert _ids(db, ScanRun, populated_org["scans"]) == set()
    assert _ids(db, ScanChange, [populated_org["change"]]) == set()
    assert _ids(db, AlertNotification, [populated_org["note"]]) == set()
    assert _ids(db, OrgInvite, [populated_org["invite"]]) == set()
    assert db.scalar(select(func.count(Membership.id)).where(Membership.org_id == org_id)) == 0

    events = db.scalars(
        select(AuditEvent).where(AuditEvent.org_id == org_id).order_by(AuditEvent.id)
    ).all()
    assert len(events) == audit_before + 1  # history kept, one new event
    assert events[-1].action == "org.deleted"
    assert events[-1].metadata_ == {
        "domains_deleted": 1,
        "members_removed": 2,
        "invites_deleted": 1,
        "schedules_cancelled": 0,
        "queued_scans_cancelled": 0,
    }

    # Unreachable afterwards, and the other org is untouched.
    assert client.get(f"/orgs/{org_id}/domains").status_code == 404
    assert org_id not in [o["id"] for o in client.get("/orgs").json()]
    assert _ids(db, Domain, [populated_org["bystander_domain"]]) == {
        populated_org["bystander_domain"]
    }
    assert _ids(db, ScanRun, [populated_org["bystander_scan"]]) == {populated_org["bystander_scan"]}


def _scheduled_domain(db: Session, org: Organization, name: str) -> Domain:
    domain = Domain(org_id=org.id, name=name, scan_interval_hours=24, next_scan_at=NOW)
    db.add(domain)
    db.flush()
    return domain


def test_delete_org_refused_while_a_scan_is_running(client, db_session, test_org):
    db = db_session
    running_domain = _scheduled_domain(db, test_org, "running.example.com")
    queued_domain = _scheduled_domain(db, test_org, "queued.example.com")
    running = _scan(db, running_domain, "running", NOW)
    queued = _scan(db, queued_domain, "queued", NOW)

    resp = client.delete(f"/orgs/{test_org.id}")

    assert resp.status_code == 409
    assert f"scan_run_id={running.id}" in resp.json()["detail"]
    db.expire_all()
    assert db.get(Organization, test_org.id).name == "Default Test Org"
    assert db.get(ScanRun, queued.id).status == "queued"
    assert db.get(Domain, queued_domain.id).scan_interval_hours == 24
    assert (
        db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.action == "org.deleted")) == 0
    )


def test_delete_org_cancels_queued_scans_and_schedules_in_the_same_transaction(
    client, db_session, test_org
):
    db = db_session
    first = _scheduled_domain(db, test_org, "sched-1.example.com")
    _scheduled_domain(db, test_org, "sched-2.example.com")
    _scan(db, first, "queued", NOW)
    bystander = _org(db, "Bystander", [(_user(db, "b@example.com").id, "owner")])
    bystander_domain = _scheduled_domain(db, bystander, "other.example.com")
    bystander_queued = _scan(db, bystander_domain, "queued", NOW)

    assert client.delete(f"/orgs/{test_org.id}").status_code == 204

    db.expire_all()
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == "org.deleted"))
    assert event.metadata_["schedules_cancelled"] == 2
    assert event.metadata_["queued_scans_cancelled"] == 1
    assert db.get(ScanRun, bystander_queued.id).status == "queued"
    assert db.get(Domain, bystander_domain.id).scan_interval_hours == 24


def test_only_owners_can_delete_an_org(client, db_session, test_org):
    db = db_session
    owner = _user(db, "boss@example.com")
    admin_org = _org(db, "Admin here", [(owner.id, "owner"), (TEST_USER_ID, "admin")])
    stranger_org = _org(db, "Not mine", [(owner.id, "owner")])

    assert client.delete(f"/orgs/{admin_org.id}").status_code == 403
    assert client.delete(f"/orgs/{stranger_org.id}").status_code == 404
    db.expire_all()
    assert db.get(Organization, admin_org.id).name == "Admin here"
    assert db.get(Organization, stranger_org.id).name == "Not mine"


# --- DELETE /me ------------------------------------------------------------------------


def test_delete_me_refused_with_409_naming_sole_owner_orgs(client, db_session, test_org):
    db = db_session
    co_owner = _user(db, "co@example.com")
    shared = _org(db, "Shared", [(TEST_USER_ID, "owner"), (co_owner.id, "owner")])

    resp = client.delete("/me")
    assert resp.status_code == 409
    orgs = resp.json()["detail"]["organizations"]
    assert orgs == [{"id": test_org.id, "name": "Default Test Org"}]
    assert shared.id not in [o["id"] for o in orgs]
    db.expire_all()
    assert db.get(User, TEST_USER_ID) is not None


def test_delete_me_removes_account_memberships_and_own_invites(client, db_session):
    db = db_session
    me = db.get(User, TEST_USER_ID)
    co_owner = _user(db, "co@example.com")
    shared = _org(db, "Shared", [(TEST_USER_ID, "owner"), (co_owner.id, "owner")])
    viewed = _org(db, "Viewed", [(co_owner.id, "owner"), (TEST_USER_ID, "viewer")])
    mine = _invite(db, viewed, me.email, accepted_at=NOW)
    theirs = _invite(db, viewed, "someone-else@example.com")
    sent_by_me = _invite(db, shared, "friend@example.com", invited_by_user_id=TEST_USER_ID)
    db.add(
        AuditEvent(
            org_id=shared.id,
            actor_type="user",
            actor_user_id=TEST_USER_ID,
            action="org.created",
            target_type="org",
            target_id=str(shared.id),
        )
    )
    db.flush()

    resp = client.delete("/me")
    assert resp.status_code == 204

    db.expire_all()
    assert db.get(User, TEST_USER_ID) is None
    assert (
        db.scalar(select(func.count(Membership.id)).where(Membership.user_id == TEST_USER_ID)) == 0
    )
    assert _ids(db, OrgInvite, [mine.id, theirs.id, sent_by_me.id]) == {theirs.id, sent_by_me.id}
    assert db.get(OrgInvite, sent_by_me.id).invited_by_user_id is None
    # Both orgs keep running for the other owner.
    assert {m.org_id for m in db.scalars(select(Membership)).all()} >= {shared.id, viewed.id}

    deleted_events = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "account.deleted").order_by(AuditEvent.org_id)
    ).all()
    assert [(e.org_id, e.metadata_["role"]) for e in deleted_events] == [
        (shared.id, "owner"),
        (viewed.id, "viewer"),
    ]
    # Earlier audit events by this user are kept (append-only).
    assert (
        db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.actor_user_id == TEST_USER_ID, AuditEvent.action == "org.created"
            )
        )
        == 1
    )


def test_suspended_user_cannot_delete_their_account(client, db_session):
    db = db_session
    me = db.get(User, TEST_USER_ID)
    me.suspended_at = NOW
    me.suspended_reason = "abuse"
    db.flush()

    resp = client.delete("/me")
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Account suspended"}
    db.expire_all()
    assert db.get(User, TEST_USER_ID) is not None


# --- Retention purge -------------------------------------------------------------------


@pytest.fixture
def aged_data(db_session: Session, test_org: Organization):
    db = db_session
    d1 = Domain(org_id=test_org.id, name="retention-1.example.com")
    d2 = Domain(org_id=test_org.id, name="retention-2.example.com")
    db.add_all([d1, d2])
    db.flush()
    old_plain = _scan(db, d1, "succeeded", OLD)
    old_baseline = _scan(db, d1, "succeeded", OLD + timedelta(days=1))
    old_failed = _scan(db, d1, "failed", OLD + timedelta(days=2))
    old_with_change = _scan(db, d1, "succeeded", OLD + timedelta(days=3))
    _change(db, d1, old_with_change, old_baseline)
    recent_latest = _scan(db, d1, "succeeded", NOW)
    old_queued = ScanRun(domain_id=d2.id, status="queued", created_at=OLD)
    db.add(old_queued)
    db.flush()
    only_success_d2 = _scan(db, d2, "succeeded", OLD + timedelta(days=5))

    notes = {
        "old_sent": _notification(db, d2, "sent", NOW - timedelta(days=91)),
        "old_failed": _notification(db, d2, "failed", NOW - timedelta(days=91)),
        "old_pending": _notification(db, d2, "pending", NOW - timedelta(days=91)),
        "recent_sent": _notification(db, d2, "sent", NOW - timedelta(days=89)),
    }
    invites = {
        "accepted_old": _invite(
            db, test_org, "a@example.com", accepted_at=NOW - timedelta(days=31)
        ),
        "expired_old": _invite(db, test_org, "b@example.com", expires_at=NOW - timedelta(days=31)),
        "revoked_recent": _invite(
            db, test_org, "c@example.com", revoked_at=NOW - timedelta(days=10)
        ),
        "pending": _invite(db, test_org, "d@example.com"),
    }
    db.add(
        AuditEvent(
            org_id=test_org.id,
            actor_type="system",
            action="org.created",
            target_type="org",
            target_id=str(test_org.id),
            created_at=OLD,
        )
    )
    db.flush()
    scans = {
        "old_plain": old_plain.id,
        "old_baseline": old_baseline.id,
        "old_failed": old_failed.id,
        "old_with_change": old_with_change.id,
        "recent_latest": recent_latest.id,
        "old_queued": old_queued.id,
        "only_success_d2": only_success_d2.id,
    }
    return scans, {k: v.id for k, v in notes.items()}, {k: v.id for k, v in invites.items()}


def test_purge_dry_run_counts_and_deletes_nothing(db_session, aged_data):
    scans, notes, invites = aged_data
    audit_before = db_session.scalar(select(func.count(AuditEvent.id)))

    counts = purge_expired(db_session, dry_run=True)

    assert counts == {"scans": 3, "alert_notifications": 2, "invites": 2}
    assert _ids(db_session, ScanRun, scans.values()) == set(scans.values())
    assert _ids(db_session, AlertNotification, notes.values()) == set(notes.values())
    assert _ids(db_session, OrgInvite, invites.values()) == set(invites.values())
    assert db_session.scalar(select(func.count(AuditEvent.id))) == audit_before


def test_purge_keeps_latest_success_baselines_and_unfinished_scans(db_session, aged_data):
    scans, notes, invites = aged_data
    audit_before = db_session.scalar(select(func.count(AuditEvent.id)))

    counts = purge_expired(db_session, dry_run=False)

    assert counts == {"scans": 3, "alert_notifications": 2, "invites": 2}
    kept_scans = {
        scans[k] for k in ("old_baseline", "recent_latest", "old_queued", "only_success_d2")
    }
    assert _ids(db_session, ScanRun, scans.values()) == kept_scans
    assert _ids(db_session, AlertNotification, notes.values()) == {
        notes["old_pending"],
        notes["recent_sent"],
    }
    assert _ids(db_session, OrgInvite, invites.values()) == {
        invites["revoked_recent"],
        invites["pending"],
    }
    assert db_session.scalar(select(func.count(AuditEvent.id))) == audit_before

    # The baseline was only protected by the change of a scan that is now purged.
    assert purge_expired(db_session, dry_run=False)["scans"] == 1
    assert _ids(db_session, ScanRun, scans.values()) == kept_scans - {scans["old_baseline"]}


def test_admin_purge_dry_run_reports_counts(db_session, aged_data, capsys):
    scans, _, _ = aged_data
    assert admin_main(["purge", "--dry-run"], session=db_session) == 0
    out = capsys.readouterr().out
    assert "Would delete 3 scan(s), 2 alert notification(s) and 2 invite(s)" in out
    assert _ids(db_session, ScanRun, scans.values()) == set(scans.values())
