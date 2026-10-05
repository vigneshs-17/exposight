"""v3.6b A7: in-memory request rate limits (429 + Retry-After) and database quotas."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api import deps
from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import AlertNotification, Domain, Membership, Organization, ScanRun, User
from asm.db.session import get_db
from asm.ratelimit import (
    API_REQUESTS_PER_MINUTE_PER_USER,
    MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY,
    MAX_DOMAINS_PER_ORG,
    MAX_MANUAL_SCANS_PER_DOMAIN_PER_HOUR,
    MAX_OWNED_ORGS_PER_USER,
    UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP,
    SlidingWindowLimiter,
)
from asm.worker.worker import ASMWorker

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


# --- Limiter unit tests ---------------------------------------------------------------


def test_limiter_allows_limit_then_returns_retry_after():
    clock = [100.0]
    limiter = SlidingWindowLimiter(clock=lambda: clock[0])
    for _ in range(3):
        assert limiter.hit("k", 3, window=60) is None
    clock[0] += 10
    assert limiter.hit("k", 3, window=60) == pytest.approx(50.0)
    assert limiter.hit("other", 3, window=60) is None  # keys are independent


def test_limiter_window_slides():
    clock = [0.0]
    limiter = SlidingWindowLimiter(clock=lambda: clock[0])
    assert limiter.hit("k", 1, window=60) is None
    assert limiter.hit("k", 1, window=60) is not None
    clock[0] += 60.0
    assert limiter.hit("k", 1, window=60) is None


def test_rejected_requests_are_not_counted():
    """A client hammering while blocked does not extend its own block."""
    clock = [0.0]
    limiter = SlidingWindowLimiter(clock=lambda: clock[0])
    limiter.hit("k", 1, window=60)
    for _ in range(50):
        limiter.hit("k", 1, window=60)
    clock[0] += 60.0
    assert limiter.hit("k", 1, window=60) is None


def test_idle_keys_are_swept():
    clock = [0.0]
    limiter = SlidingWindowLimiter(clock=lambda: clock[0])
    for i in range(500):
        limiter.hit(f"ip:{i}", 5, window=60)
    clock[0] += 120.0
    for _ in range(1000):
        limiter.hit("active", 10_000, window=60)
    assert set(limiter._hits) == {"active"}


# --- Unauthenticated limit (middleware, per IP) ----------------------------------------


def test_unauthenticated_requests_limited_per_ip_with_retry_after():
    with TestClient(app) as client:
        for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
            assert client.get("/").status_code == 200
        blocked = client.get("/")
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["Retry-After"]) <= 60
    assert blocked.headers["X-Content-Type-Options"] == "nosniff"


def test_forwarded_for_header_from_client_does_not_reset_limit():
    """The app never reads X-Forwarded-For itself (uvicorn trusts it only from Caddy)."""
    with TestClient(app) as client:
        for i in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
            client.get("/", headers={"X-Forwarded-For": f"203.0.113.{i}"})
        blocked = client.get("/", headers={"X-Forwarded-For": "198.51.100.7"})
    assert blocked.status_code == 429


def test_static_assets_and_health_are_not_limited():
    with TestClient(app) as client:
        for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP + 5):
            assert client.get("/static/css/app.css").status_code == 200
        assert client.get("/").status_code == 200


# --- Authenticated limits (get_current_user) -------------------------------------------


@pytest.fixture
def real_auth_client(client):
    """The conftest client, but with the real get_current_user (authentication is stubbed)."""
    app.dependency_overrides.pop(get_current_user, None)
    yield client


@pytest.mark.db
def test_authenticated_user_limited_per_minute(real_auth_client, db_session, monkeypatch):
    user = db_session.get(User, TEST_USER_ID)
    monkeypatch.setattr(deps, "_authenticate", lambda *args: user)
    headers = {"Authorization": "Bearer stub"}
    for _ in range(API_REQUESTS_PER_MINUTE_PER_USER):
        assert real_auth_client.get("/orgs", headers=headers).status_code == 200
    blocked = real_auth_client.get("/orgs", headers=headers)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_failed_authentication_counts_against_ip_limit(monkeypatch):
    """Invalid tokens cannot be sprayed without limit."""

    def reject(*args):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bad token")

    monkeypatch.setattr(deps, "_authenticate", reject)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_db] = lambda: iter([None])  # auth fails before any query
    try:
        with TestClient(app) as client:
            headers = {"Authorization": "Bearer junk"}
            for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
                assert client.get("/orgs", headers=headers).status_code == 401
            blocked = client.get("/orgs", headers=headers)
    finally:
        app.dependency_overrides.clear()
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


# --- Quotas (database) ----------------------------------------------------------------


@pytest.fixture
def owned_org(client, db_session: Session) -> Organization:
    org = Organization(name="Quota Org")
    db_session.add(org)
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=TEST_USER_ID, role="owner"))
    db_session.commit()
    return org


@pytest.mark.db
def test_domain_quota_per_org(client, db_session, owned_org):
    for i in range(MAX_DOMAINS_PER_ORG):
        db_session.add(Domain(org_id=owned_org.id, name=f"q{i}.example.com"))
    db_session.commit()

    resp = client.post(f"/orgs/{owned_org.id}/domains", json={"name": "one-more.example.com"})
    assert resp.status_code == 403
    assert "quota" in resp.json()["detail"].lower()

    other = client.post("/orgs", json={"name": "Second Org"}).json()["id"]
    assert client.post(f"/orgs/{other}/domains", json={"name": "ok.example.com"}).status_code == 201


@pytest.mark.db
def test_owned_org_quota_per_user(client, db_session):
    for i in range(MAX_OWNED_ORGS_PER_USER):
        assert client.post("/orgs", json={"name": f"Org {i}"}).status_code == 201
    resp = client.post("/orgs", json={"name": "One too many"})
    assert resp.status_code == 403
    assert "quota" in resp.json()["detail"].lower()


def _verified_domain(db_session, org) -> Domain:
    domain = Domain(org_id=org.id, name="scan-quota.example.com", verification_status="verified")
    db_session.add(domain)
    db_session.commit()
    return domain


@pytest.mark.db
def test_manual_scan_quota_per_domain_per_hour(client, db_session, owned_org):
    domain = _verified_domain(db_session, owned_org)
    oldest = datetime.now(UTC) - timedelta(minutes=50)
    for i in range(MAX_MANUAL_SCANS_PER_DOMAIN_PER_HOUR):
        db_session.add(
            ScanRun(
                domain_id=domain.id,
                status="succeeded",
                trigger="manual",
                created_at=oldest + timedelta(minutes=i),
            )
        )
    db_session.commit()

    resp = client.post(f"/orgs/{owned_org.id}/domains/{domain.id}/scans")
    assert resp.status_code == 429
    retry_after = int(resp.headers["Retry-After"])
    assert 9 * 60 <= retry_after <= 11 * 60  # oldest manual scan leaves the window in ~10 min


@pytest.mark.db
def test_scheduled_and_old_scans_do_not_count(client, db_session, owned_org):
    domain = _verified_domain(db_session, owned_org)
    now = datetime.now(UTC)
    for i in range(MAX_MANUAL_SCANS_PER_DOMAIN_PER_HOUR):
        db_session.add(ScanRun(domain_id=domain.id, status="succeeded", trigger="scheduled",
                               created_at=now - timedelta(minutes=i + 1)))
        db_session.add(ScanRun(domain_id=domain.id, status="succeeded", trigger="manual",
                               created_at=now - timedelta(hours=2, minutes=i)))
    db_session.commit()

    resp = client.post(f"/orgs/{owned_org.id}/domains/{domain.id}/scans")
    assert resp.status_code == 202, resp.text


def _seed_sent_alerts(db_engine, count: int) -> tuple[int, int, datetime]:
    with Session(db_engine) as session:
        org = Organization(name="Alert Quota Org")
        session.add(org)
        session.flush()
        domain = Domain(org_id=org.id, name="alert-quota.example.com")
        session.add(domain)
        session.flush()
        oldest = datetime.now(UTC) - timedelta(hours=20)
        for i in range(count):
            session.add(
                AlertNotification(
                    domain_id=domain.id,
                    recipient=f"r{i}@example.com",
                    subject="s",
                    body="b",
                    status="sent",
                    attempts=1,
                    sent_at=oldest + timedelta(minutes=i),
                )
            )
        pending = AlertNotification(
            domain_id=domain.id,
            recipient="next@example.com",
            subject="s",
            body="b",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add(pending)
        session.commit()
        return domain.id, pending.id, oldest


@pytest.mark.db
def test_daily_alert_quota_defers_without_dropping(db_engine, clean_db):
    _, pending_id, oldest = _seed_sent_alerts(db_engine, MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY)
    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        assert worker.deliver_pending_alerts() == 0
    mock_send.assert_not_called()

    with Session(db_engine) as session:
        row = session.get(AlertNotification, pending_id)
        assert row.status == "pending"
        assert row.attempts == 0
        assert abs((row.next_attempt_at - (oldest + timedelta(hours=24))).total_seconds()) < 2


@pytest.mark.db
def test_alerts_below_daily_quota_are_sent(db_engine, clean_db):
    _, pending_id, _ = _seed_sent_alerts(db_engine, MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY - 1)
    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        assert worker.deliver_pending_alerts() == 1
    mock_send.assert_called_once()
