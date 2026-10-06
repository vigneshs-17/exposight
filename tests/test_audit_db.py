"""Database integration tests for audit logging, triggers, RBAC, and pagination."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from asm.admin import move_domain, revoke_verification, verify_domain
from asm.api.deps import get_current_user
from asm.api.main import app
from asm.audit import AUDIT_ACTIONS, record_event
from asm.db.models import AuditEvent, Domain, Membership, Organization, User
from asm.verification import VerificationOutcome
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


def test_audit_events_append_only_trigger(db_session: Session, test_org: Organization):
    """Direct UPDATE, DELETE, and TRUNCATE statements on audit_events are prohibited by trigger."""
    ev = record_event(
        db_session,
        org_id=test_org.id,
        actor_type="system",
        action="verification.override_expired",
        target_type="domain",
        target_id="999",
        metadata={},
    )
    db_session.commit()
    ev_id = ev.id

    # 1. UPDATE must fail
    with pytest.raises(DBAPIError, match="audit_events is append-only"):
        db_session.execute(
            text("UPDATE audit_events SET action = 'tampered' WHERE id = :id"),
            {"id": ev_id},
        )
    db_session.rollback()

    # 2. DELETE must fail
    with pytest.raises(DBAPIError, match="audit_events is append-only"):
        db_session.execute(
            text("DELETE FROM audit_events WHERE id = :id"),
            {"id": ev_id},
        )
    db_session.rollback()

    # 3. TRUNCATE must fail
    with pytest.raises(DBAPIError, match="audit_events is append-only"):
        db_session.execute(text("TRUNCATE audit_events;"))
    db_session.rollback()


def test_clean_db_reenables_trigger(clean_db, db_engine):
    """clean_db truncates and explicitly re-enables the trigger in the same transaction."""
    with Session(db_engine) as session:
        # Check pg_trigger status: 'O' means Enabled (origin)
        status = session.execute(
            text("SELECT tgenabled FROM pg_trigger WHERE tgname = 'trg_audit_events_append_only';")
        ).scalar()
        assert status == "O"

        # Insert event and assert UPDATE still fails
        session.execute(
            text(
                "INSERT INTO organizations (id, name, created_at) "
                "VALUES (9999, 'Trigger Org', now()) ON CONFLICT DO NOTHING;"
            )
        )
        session.execute(
            text(
                "INSERT INTO audit_events "
                "(org_id, actor_type, action, target_type, target_id, metadata, created_at) "
                "VALUES (9999, 'system', 'verification.override_expired', 'domain', '1', "
                "'{}'::jsonb, now());"
            )
        )
        session.commit()

        with pytest.raises(DBAPIError, match="audit_events is append-only"):
            session.execute(
                text("UPDATE audit_events SET action = 'tampered' WHERE org_id = 9999;")
            )
        session.rollback()


def test_audit_event_rollback_atomicity(db_session: Session, test_org: Organization):
    """If an operation rolls back, the recorded audit event is rolled back too."""
    record_event(
        db_session,
        org_id=test_org.id,
        actor_type="user",
        action="domain.created",
        target_type="domain",
        target_id="123",
        metadata={"name": "rollback.test"},
    )
    db_session.rollback()

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "domain.created",
            AuditEvent.target_id == "123",
        )
    ).all()
    assert len(events) == 0


def test_audit_events_api_rbac(client: TestClient, db_session: Session, test_org: Organization):
    """Only admins and owners can view audit events; viewers 403, non-members 404."""
    # Record an event
    record_event(
        db_session,
        org_id=test_org.id,
        actor_type="system",
        action="verification.override_expired",
        target_type="domain",
        target_id="1",
        metadata={},
    )
    db_session.commit()

    # 1. Owner (default test_user is owner) -> 200 OK
    resp_owner = client.get(f"/orgs/{test_org.id}/audit-events")
    assert resp_owner.status_code == 200
    assert len(resp_owner.json()) >= 1

    # 2. Admin -> 200 OK
    admin_user = User(id=uuid.uuid4(), email="admin@example.com")
    db_session.add(admin_user)
    db_session.flush()
    db_session.add(Membership(org_id=test_org.id, user_id=admin_user.id, role="admin"))
    db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: admin_user
    resp_admin = client.get(f"/orgs/{test_org.id}/audit-events")
    assert resp_admin.status_code == 200

    # 3. Viewer -> 403 Forbidden
    viewer_user = User(id=uuid.uuid4(), email="viewer@example.com")
    db_session.add(viewer_user)
    db_session.flush()
    db_session.add(Membership(org_id=test_org.id, user_id=viewer_user.id, role="viewer"))
    db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: viewer_user
    resp_viewer = client.get(f"/orgs/{test_org.id}/audit-events")
    assert resp_viewer.status_code == 403

    # 4. Non-member -> 404 Not Found
    outsider_user = User(id=uuid.uuid4(), email="outsider@example.com")
    db_session.add(outsider_user)
    db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: outsider_user
    resp_outsider = client.get(f"/orgs/{test_org.id}/audit-events")
    assert resp_outsider.status_code == 404

    app.dependency_overrides.pop(get_current_user, None)


def test_audit_events_pagination_and_filtering(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Audit events listing supports limit, keyset cursor, domain_id, and action filters."""
    # Create 5 audit events
    events = []
    for i in range(1, 6):
        target_id = "10" if i % 2 == 1 else "20"
        action = "domain.created" if i <= 3 else "domain.schedule_changed"
        meta = (
            {"name": f"test{i}.com"}
            if i <= 3
            else {"old_interval_hours": None, "new_interval_hours": 24}
        )
        ev = record_event(
            db_session,
            org_id=test_org.id,
            actor_type="user",
            action=action,
            target_type="domain",
            target_id=target_id,
            metadata=meta,
        )
        events.append(ev)
    db_session.commit()

    # 1. Default ordering newest first (id desc)
    resp = client.get(f"/orgs/{test_org.id}/audit-events?limit=10")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 5
    ids = [item["id"] for item in items]
    assert ids == sorted(ids, reverse=True)

    # 2. Filter by domain_id="10"
    resp_dom = client.get(f"/orgs/{test_org.id}/audit-events?domain_id=10")
    assert resp_dom.status_code == 200
    dom_items = resp_dom.json()
    assert all(item["target_id"] == "10" and item["target_type"] == "domain" for item in dom_items)

    # 3. Filter by action="domain.schedule_changed"
    resp_act = client.get(f"/orgs/{test_org.id}/audit-events?action=domain.schedule_changed")
    assert resp_act.status_code == 200
    act_items = resp_act.json()
    assert all(item["action"] == "domain.schedule_changed" for item in act_items)

    # 4. Keyset cursor: before_id
    mid_id = ids[2]
    resp_cursor = client.get(f"/orgs/{test_org.id}/audit-events?before_id={mid_id}&limit=2")
    assert resp_cursor.status_code == 200
    cursor_items = resp_cursor.json()
    assert len(cursor_items) <= 2
    assert all(item["id"] < mid_id for item in cursor_items)


def test_lapse_with_ip_in_dns_detail_succeeds(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Domain lapse still succeeds when DNS detail text contains an IP address."""
    # Create domain
    domain = Domain(
        org_id=test_org.id,
        name="lapse-dns-ip.example.com",
        verification_status="verified",
        verification_token="token_abc",
        verification_method="dns_txt",
        consecutive_misses=1,
    )
    db_session.add(domain)
    db_session.commit()
    db_session.refresh(domain)

    # Mock DNS check returning ABSENT with detail text containing an IP address
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "NXDOMAIN resolver returned 192.168.1.53#53"),
    ):
        resp = client.post(f"/orgs/{test_org.id}/domains/{domain.id}/verification/check")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "lapsed"

    # Verify verification.lapsed audit event was recorded with clean metadata
    lapsed_event = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.lapsed",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert lapsed_event is not None
    assert lapsed_event.metadata_ == {"consecutive_misses": 2, "outcome": "absent"}


def test_org_name_and_operator_reason_redacted_in_db(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Org name and operator reason containing email and IP succeed and are stored as [redacted]."""
    # 1. Create org with email and IP in name
    resp_org = client.post(
        "/orgs",
        json={"name": "Org for alice@target.com server 10.0.0.99"},
    )
    assert resp_org.status_code == 201
    new_org_id = resp_org.json()["id"]

    ev_org = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == new_org_id,
            AuditEvent.action == "org.created",
        )
    )
    assert ev_org is not None
    assert ev_org.metadata_["name"] == "Org for [redacted] server [redacted]"

    # 2. Operator verify with email and IP in reason
    domain = Domain(
        org_id=test_org.id,
        name="operator-redact.example.com",
        verification_status="pending",
        verification_token="tok123",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.commit()
    db_session.refresh(domain)

    ret = verify_domain(
        db_session,
        domain.id,
        reason="Granted by bob@corp.org from 172.16.1.1",
        expires_in_days=30,
    )
    assert ret == 0

    ev_op = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.operator_granted",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert ev_op is not None
    assert ev_op.metadata_["reason"] == "Granted by [redacted] from [redacted]"


def test_admin_cli_audit_events(db_session: Session, test_org: Organization):
    """Admin CLI commands verify-domain, revoke, and move-domain record audit events."""
    quarantine_org = Organization(name="Quarantine Org", system_kind="legacy_quarantine")
    db_session.add(quarantine_org)
    db_session.flush()

    domain = Domain(
        org_id=quarantine_org.id,
        name="cli-admin.example.com",
        verification_status="pending",
        verification_token="cli_tok",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.commit()
    db_session.refresh(domain)

    # 1. move_domain records dual events (one for source org, one for target org)
    ret_move = move_domain(db_session, domain.id, test_org.id)
    assert ret_move == 0

    src_ev = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == quarantine_org.id,
            AuditEvent.action == "domain.moved",
            AuditEvent.target_id == str(domain.id),
        )
    )
    tgt_ev = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "domain.moved",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert src_ev is not None
    assert src_ev.metadata_["to_org_id"] == test_org.id
    assert tgt_ev is not None
    assert tgt_ev.metadata_["from_org_id"] == quarantine_org.id

    # 2. verify_domain records verification.operator_granted
    ret_verify = verify_domain(
        db_session, domain.id, reason="Admin verification", expires_in_days=14
    )
    assert ret_verify == 0

    ev_grant = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.operator_granted",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert ev_grant is not None
    assert ev_grant.metadata_["reason"] == "Admin verification"
    assert ev_grant.metadata_["expires_in_days"] == 14

    # 3. revoke_verification records verification.operator_revoked
    ret_revoke = revoke_verification(db_session, domain.id, reason="Revoking admin grant")
    assert ret_revoke == 0

    ev_revoke = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.operator_revoked",
            AuditEvent.target_id == str(domain.id),
        )
    )
    assert ev_revoke is not None
    assert ev_revoke.metadata_["reason"] == "Revoking admin grant"


def test_worker_audit_events(clean_db, db_engine, lifecycle_org: Organization):
    """Worker background operations record verification.override_expired and verification.lapsed."""
    worker = ASMWorker(engine=db_engine)

    # 1. Expire operator override
    with Session(db_engine) as session:
        dom1 = Domain(
            org_id=lifecycle_org.id,
            name="expire-override.example.com",
            verification_status="verified",
            verification_token="tok1",
            verification_method="operator",
            verification_expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        session.add(dom1)
        session.commit()
        dom1_id = dom1.id

    expired_count = worker.expire_operator_overrides()
    assert expired_count >= 1

    with Session(db_engine) as session:
        ev_exp = session.scalar(
            select(AuditEvent).where(
                AuditEvent.org_id == lifecycle_org.id,
                AuditEvent.action == "verification.override_expired",
                AuditEvent.target_id == str(dom1_id),
            )
        )
        assert ev_exp is not None
        assert ev_exp.actor_type == "system"

    # 2. Reverification lapse
    with Session(db_engine) as session:
        dom2 = Domain(
            org_id=lifecycle_org.id,
            name="reverify-lapse.example.com",
            verification_status="verified",
            verification_token="tok2",
            verification_method="dns_txt",
            consecutive_misses=1,
            next_reverification_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        session.add(dom2)
        session.commit()
        dom2_id = dom2.id

    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "NXDOMAIN"),
    ):
        reverified_count = worker.reverify_due_domains()
        assert reverified_count >= 1

    with Session(db_engine) as session:
        ev_lapse = session.scalar(
            select(AuditEvent).where(
                AuditEvent.org_id == lifecycle_org.id,
                AuditEvent.action == "verification.lapsed",
                AuditEvent.target_id == str(dom2_id),
            )
        )
        assert ev_lapse is not None
        assert ev_lapse.actor_type == "system"
        assert ev_lapse.metadata_ == {"consecutive_misses": 2, "outcome": "absent"}


def test_all_mutating_routes_map_to_audit_action():
    """Every mutating route in the application (excluding /health) maps to an audit action."""
    route_action_map = {
        ("POST", "/orgs"): "org.created",
        ("DELETE", "/orgs/{org_id}"): "org.deleted",
        ("DELETE", "/me"): "account.deleted",
        ("POST", "/orgs/{org_id}/invites"): "invite.created",
        ("DELETE", "/orgs/{org_id}/invites/{invite_id}"): "invite.revoked",
        ("POST", "/invites/accept"): "membership.added",
        ("PATCH", "/orgs/{org_id}/members/{user_id}"): "membership.role_changed",
        ("DELETE", "/orgs/{org_id}/members/{user_id}"): "membership.removed",
        ("POST", "/orgs/{org_id}/domains"): "domain.created",
        ("POST", "/orgs/{org_id}/domains/{domain_id}/verification/check"): "verification.checked",
        ("POST", "/orgs/{org_id}/domains/{domain_id}/verification/rotate"): "verification.rotated",
        ("POST", "/orgs/{org_id}/domains/{domain_id}/scans"): "scan.queued",
        ("PUT", "/orgs/{org_id}/domains/{domain_id}/schedule"): "domain.schedule_changed",
        ("PUT", "/orgs/{org_id}/domains/{domain_id}/alerts"): "domain.alerts_changed",
    }

    found_mutating_routes = set()

    for r in app.routes:
        # Check direct routes and included router routes
        sub_routes = getattr(getattr(r, "original_router", None), "routes", [r])
        for sub in sub_routes:
            methods = getattr(sub, "methods", set())
            path = getattr(sub, "path", "")
            if path in ("/health", "/docs", "/redoc", "/openapi.json"):
                continue
            for m in methods:
                if m in ("POST", "PUT", "PATCH", "DELETE"):
                    found_mutating_routes.add((m, path))

    # 410 Gone (v3.6b): changes nothing, so it records nothing.
    gone_routes = {("POST", "/orgs/{org_id}/members")}
    assert gone_routes <= found_mutating_routes
    found_mutating_routes -= gone_routes

    # All discovered routes must be in our map and map to a recognized audit action
    assert len(found_mutating_routes) == 14
    for method, path in found_mutating_routes:
        assert (method, path) in route_action_map, f"Unmapped mutating route: {method} {path}"
        action = route_action_map[(method, path)]
        assert action in AUDIT_ACTIONS, f"Action {action} for {method} {path} not in AUDIT_ACTIONS"


def test_api_membership_added_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Accepting an invite writes exactly one membership.added audit event (v3.6b A2)."""
    target_user = User(id=uuid.uuid4(), email="newbie@example.com")
    db_session.add(target_user)
    db_session.commit()

    invite = client.post(
        f"/orgs/{test_org.id}/invites",
        json={"email": "newbie@example.com", "role": "viewer"},
    )
    assert invite.status_code == 201

    inviter_override = app.dependency_overrides[get_current_user]
    app.dependency_overrides[get_current_user] = lambda: target_user
    try:
        resp = client.post("/invites/accept", json={"token": invite.json()["token"]})
    finally:
        app.dependency_overrides[get_current_user] = inviter_override
    assert resp.status_code == 200

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "membership.added",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == target_user.id  # the person who accepted
    assert ev.target_type == "membership"
    assert ev.metadata_ == {
        "user_id": str(target_user.id),
        "role": "viewer",
        "via": "invite",
        "invite_id": invite.json()["id"],
    }
    assert ev.target_id.isdigit()


def test_api_membership_role_changed_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """PATCH /orgs/{org_id}/members/{user_id} writes one membership.role_changed audit event."""
    member_user = User(id=uuid.uuid4(), email="promotee@example.com")
    db_session.add(member_user)
    db_session.flush()
    member = Membership(org_id=test_org.id, user_id=member_user.id, role="viewer")
    db_session.add(member)
    db_session.commit()

    resp = client.patch(
        f"/orgs/{test_org.id}/members/{member_user.id}",
        json={"role": "admin"},
    )
    assert resp.status_code == 200

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "membership.role_changed",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "membership"
    assert ev.target_id == str(member.id)
    assert ev.metadata_ == {
        "user_id": str(member_user.id),
        "old_role": "viewer",
        "new_role": "admin",
    }


def test_api_membership_removed_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """DELETE /orgs/{org_id}/members/{user_id} writes one membership.removed audit event."""
    remove_user = User(id=uuid.uuid4(), email="removeme@example.com")
    db_session.add(remove_user)
    db_session.flush()
    member = Membership(org_id=test_org.id, user_id=remove_user.id, role="admin")
    db_session.add(member)
    db_session.commit()
    member_id = member.id

    resp = client.delete(f"/orgs/{test_org.id}/members/{remove_user.id}")
    assert resp.status_code == 204

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "membership.removed",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "membership"
    assert ev.target_id == str(member_id)
    assert ev.metadata_ == {"user_id": str(remove_user.id), "role": "admin"}


def test_api_domain_alerts_changed_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """PUT /domains/{domain_id}/alerts writes one domain.alerts_changed audit event."""
    domain = Domain(
        org_id=test_org.id,
        name="alerts-test.example.com",
        verification_status="verified",
        verification_token="tok_alerts",
        verification_method="dns_txt",
        alerts_enabled=False,
        alert_min_severity="MEDIUM",
    )
    db_session.add(domain)
    db_session.commit()

    resp = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["alerts@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert resp.status_code == 200

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "domain.alerts_changed",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "domain"
    assert ev.target_id == str(domain.id)
    assert ev.metadata_ == {
        "old_enabled": False,
        "new_enabled": True,
        "old_min_severity": "MEDIUM",
        "new_min_severity": "HIGH",
        "old_recipient_count": 0,
        "new_recipient_count": 1,
        "recipients_changed": True,
    }


def test_api_verification_checked_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """POST /domains/{id}/verification/check writes exactly one verification.checked event."""
    domain = Domain(
        org_id=test_org.id,
        name="check-match.example.com",
        verification_status="pending",
        verification_token="tok_check_match",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.commit()

    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Exact match"),
    ):
        resp = client.post(f"/orgs/{test_org.id}/domains/{domain.id}/verification/check")
        assert resp.status_code == 200

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.checked",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "domain"
    assert ev.target_id == str(domain.id)
    assert ev.metadata_ == {"outcome": "match", "consecutive_misses": 0}


def test_api_verification_rotated_audit_event(
    client: TestClient, db_session: Session, test_org: Organization
):
    """POST /domains/{id}/verification/rotate writes exactly one verification.rotated event."""
    domain = Domain(
        org_id=test_org.id,
        name="rotate-test.example.com",
        verification_status="verified",
        verification_token="tok_old",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.commit()

    resp = client.post(f"/orgs/{test_org.id}/domains/{domain.id}/verification/rotate")
    assert resp.status_code == 200

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "verification.rotated",
        )
    ).all()
    assert len(events) == 1
    ev = events[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "domain"
    assert ev.target_id == str(domain.id)
    assert ev.metadata_ == {}


def test_api_scan_queued_audit_event_and_idempotency(
    client: TestClient, db_session: Session, test_org: Organization
):
    """POST /scans writes one scan.queued event and replay writes NO second event."""
    domain = Domain(
        org_id=test_org.id,
        name="scan-queued.example.com",
        verification_status="verified",
        verification_token="tok_scan",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.commit()

    idempotency_key = "idemp-key-999"
    resp1 = client.post(
        f"/orgs/{test_org.id}/domains/{domain.id}/scans",
        headers={"Idempotency-Key": idempotency_key},
    )
    assert resp1.status_code == 202
    scan_id = resp1.json()["id"]

    events1 = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "scan.queued",
        )
    ).all()
    assert len(events1) == 1
    ev = events1[0]
    assert ev.actor_type == "user"
    assert ev.actor_user_id == uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert ev.target_type == "domain"
    assert ev.target_id == str(domain.id)
    assert ev.metadata_ == {"scan_run_id": scan_id, "trigger": "manual"}

    # Replay POST /scans with the same Idempotency-Key
    resp2 = client.post(
        f"/orgs/{test_org.id}/domains/{domain.id}/scans",
        headers={"Idempotency-Key": idempotency_key},
    )
    assert resp2.status_code == 200

    # Assert NO second scan.queued event was written
    events2 = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.org_id == test_org.id,
            AuditEvent.action == "scan.queued",
        )
    ).all()
    assert len(events2) == 1

