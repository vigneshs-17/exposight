"""Database integration tests for scan-detail UI route with real PostgreSQL database.

Verifies:
1. The changed scan-detail ScanResult query correctly loads discover and score stages.
2. Partial-coverage truncation notices for:
   - Hostname cap exceeded (hostname_cap_exceeded)
   - Provider entry/page limit reached (provider_entry_limit)
   - Combined provider and hostname cap (provider_and_hostname_cap_exceeded)
   - Historical / legacy reports lacking truncation_reason
3. Multi-tenant isolation:
   - require_org_role membership check denies access to other orgs (404 Not Found)
   - get_scan_for_org filters (ScanRun.id == scan_id AND Domain.org_id == org_id) (404 Not Found)
   - Non-members receive anti-enumeration 404 Not Found
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import sqlalchemy.event
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import Domain, Membership, Organization, ScanResult, ScanRun, ScanStage, User
from asm.db.session import get_db

pytestmark = pytest.mark.db


def _make_client_for_user(user: User, db_session: Session) -> TestClient:
    """Create a TestClient authenticated as the specified user."""

    def _override_user():
        return user

    def _override_db():
        yield db_session

    app.dependency_overrides[get_current_user] = _override_user
    app.dependency_overrides[get_db] = _override_db
    return TestClient(app)


@pytest.fixture
def scan_detail_db_fixture(db_session: Session):
    """Fixture creating two distinct organizations, members, domains, and scans."""
    user_a = User(id=uuid.uuid4(), email="user_a@tenant-a.example")
    user_b = User(id=uuid.uuid4(), email="user_b@tenant-b.example")
    user_outsider = User(id=uuid.uuid4(), email="outsider@external.example")
    db_session.add_all([user_a, user_b, user_outsider])
    db_session.flush()

    org_a = Organization(name="Tenant Alpha")
    org_b = Organization(name="Tenant Beta")
    db_session.add_all([org_a, org_b])
    db_session.flush()

    db_session.add_all([
        Membership(org_id=org_a.id, user_id=user_a.id, role="viewer"),
        Membership(org_id=org_b.id, user_id=user_b.id, role="viewer"),
    ])
    db_session.flush()

    domain_a = Domain(
        org_id=org_a.id,
        name="alpha.example.com",
        verification_status="verified",
        verification_token="tok-alpha-123",
        verification_method="dns_txt",
    )
    domain_b = Domain(
        org_id=org_b.id,
        name="beta.example.com",
        verification_status="verified",
        verification_token="tok-beta-456",
        verification_method="dns_txt",
    )
    db_session.add_all([domain_a, domain_b])
    db_session.flush()

    scan_a = ScanRun(
        domain_id=domain_a.id,
        status="succeeded",
        trigger="manual",
    )
    scan_b = ScanRun(
        domain_id=domain_b.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add_all([scan_a, scan_b])
    db_session.flush()

    return {
        "user_a": user_a,
        "user_b": user_b,
        "user_outsider": user_outsider,
        "org_a": org_a,
        "org_b": org_b,
        "domain_a": domain_a,
        "domain_b": domain_b,
        "scan_a": scan_a,
        "scan_b": scan_b,
    }


def test_scan_detail_query_loads_discover_and_score_stages(
    scan_detail_db_fixture, db_session: Session
):
    """Verify get_org_scan_detail_ui queries only discover and score, excluding portscan."""
    fix = scan_detail_db_fixture
    scan_id = fix["scan_a"].id
    org_id = fix["org_a"].id

    stage_disc = ScanStage(
        scan_run_id=scan_id, stage="discover", status="succeeded", duration_ms=100
    )
    stage_score = ScanStage(
        scan_run_id=scan_id, stage="score", status="succeeded", duration_ms=50
    )
    db_session.add_all([stage_disc, stage_score])

    disc_res = ScanResult(
        scan_run_id=scan_id,
        stage="discover",
        report={
            "domain": "alpha.example.com",
            "truncated": False,
            "counts": {"selected_hosts": 5, "observed_hosts": 5},
            "results": [],
            "source": "crt.sh",
        },
    )
    score_res = ScanResult(
        scan_run_id=scan_id,
        stage="score",
        report={
            "domain": "alpha.example.com",
            "generated_utc": "2026-10-16T00:00:00Z",
            "inputs_present": ["discover", "probe", "inspect", "score"],
            "domain_score": 10,
            "domain_band": "CRITICAL",
            "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "hosts": [
                {
                    "subdomain": "alpha.example.com",
                    "score": 10,
                    "band": "CRITICAL",
                    "findings": [
                        {
                            "id": "PORT_CONFIRMED_DB",
                            "title": "Confirmed Exposed Database Service",
                            "tier": "CRITICAL",
                            "points": 10,
                            "source": "portscan",
                            "host": "alpha.example.com",
                            "port": 5432,
                            "evidence": "PostgreSQL 16 handshake banner observed",
                            "why_it_matters": "Exposed database service responded directly.",
                        }
                    ],
                }
            ],
            "domain_findings": [],
        },
    )
    port_res = ScanResult(
        scan_run_id=scan_id,
        stage="portscan",
        report={"unneeded_heavy_data": "x" * 50000},
    )
    db_session.add_all([disc_res, score_res, port_res])
    db_session.flush()

    # Expunge port_res to test ORM loading: if the route queries portscan,
    # port_res will be loaded back into db_session's identity map.
    db_session.expunge(port_res)
    assert port_res not in db_session

    executed_sql: list[tuple[str, Any]] = []

    def before_cursor_execute_hook(
        conn, cursor, statement, parameters, context, executemany
    ):
        executed_sql.append((statement, parameters))

    sqlalchemy.event.listen(
        db_session.bind, "before_cursor_execute", before_cursor_execute_hook
    )
    try:
        client = _make_client_for_user(fix["user_a"], db_session)
        response = client.get(f"/ui/orgs/{org_id}/scans/{scan_id}")
    finally:
        sqlalchemy.event.remove(
            db_session.bind, "before_cursor_execute", before_cursor_execute_hook
        )

    assert response.status_code == 200

    # 1. Observe executed SQL: verify stage IN restriction on scan_results
    scan_result_queries = [
        (stmt, params) for stmt, params in executed_sql if "scan_results" in stmt.lower()
    ]
    assert len(scan_result_queries) == 1
    stmt, params = scan_result_queries[0]
    stmt_lower = stmt.lower()
    assert "scan_results.stage in" in stmt_lower or "stage in" in stmt_lower

    if isinstance(params, dict):
        param_values = list(params.values())
    elif isinstance(params, (list, tuple)):
        param_values = list(params)
    else:
        param_values = []

    assert "discover" in param_values
    assert "score" in param_values
    assert "portscan" not in param_values

    # 2. Verify ORM loading: portscan result was excluded and never loaded into session
    assert port_res not in db_session

    # 3. Verify HTML rendering: findings rendered, heavy report excluded
    html = response.text
    assert "alpha.example.com" in html
    assert "discover" in html.lower()
    assert "Confirmed Exposed Database Service" in html
    assert "Critical" in html
    assert "tier-critical" in html
    assert "alpha.example.com:5432" in html
    assert "PostgreSQL 16 handshake banner observed" in html
    assert "unneeded_heavy_data" not in html


def test_scan_detail_hostname_cap_truncation_notice(
    scan_detail_db_fixture, db_session: Session
):
    """Verify partial-coverage notice rendered when hostname cap was exceeded."""
    fix = scan_detail_db_fixture
    scan_id = fix["scan_a"].id
    org_id = fix["org_a"].id

    stage_disc = ScanStage(
        scan_run_id=scan_id, stage="discover", status="succeeded", duration_ms=210
    )
    db_session.add(stage_disc)

    disc_res = ScanResult(
        scan_run_id=scan_id,
        stage="discover",
        report={
            "domain": "alpha.example.com",
            "truncated": True,
            "truncation_reason": "hostname_cap_exceeded",
            "counts": {"selected_hosts": 1000, "observed_hosts": 3250},
            "source": "crt.sh",
        },
    )
    db_session.add(disc_res)
    db_session.flush()

    client = _make_client_for_user(fix["user_a"], db_session)
    response = client.get(f"/ui/orgs/{org_id}/scans/{scan_id}")
    assert response.status_code == 200
    html = response.text
    assert "Discovery capped at 1000 hostnames (3250 observed)." in html
    assert "Remaining hostnames were excluded from scanning." in html


def test_scan_detail_provider_limit_notice(
    scan_detail_db_fixture, db_session: Session
):
    """Verify partial-coverage notice rendered when provider limit was reached."""
    fix = scan_detail_db_fixture
    scan_id = fix["scan_a"].id
    org_id = fix["org_a"].id

    stage_disc = ScanStage(
        scan_run_id=scan_id, stage="discover", status="succeeded", duration_ms=150
    )
    db_session.add(stage_disc)

    disc_res = ScanResult(
        scan_run_id=scan_id,
        stage="discover",
        report={
            "domain": "alpha.example.com",
            "truncated": True,
            "truncation_reason": "provider_entry_limit",
            "counts": {"selected_hosts": 500, "observed_hosts": 500},
            "source": "Cert Spotter",
        },
    )
    db_session.add(disc_res)
    db_session.flush()

    client = _make_client_for_user(fix["user_a"], db_session)
    response = client.get(f"/ui/orgs/{org_id}/scans/{scan_id}")
    assert response.status_code == 200
    html = response.text
    msg = "Provider (Cert Spotter) entry or page limit reached. Discovery may be incomplete."
    assert msg in html


def test_scan_detail_combined_limit_notice(
    scan_detail_db_fixture, db_session: Session
):
    """Verify partial-coverage notice when provider limit and hostname cap both occur."""
    fix = scan_detail_db_fixture
    scan_id = fix["scan_a"].id
    org_id = fix["org_a"].id

    stage_disc = ScanStage(
        scan_run_id=scan_id, stage="discover", status="succeeded", duration_ms=300
    )
    db_session.add(stage_disc)

    disc_res = ScanResult(
        scan_run_id=scan_id,
        stage="discover",
        report={
            "domain": "alpha.example.com",
            "truncated": True,
            "truncation_reason": "provider_and_hostname_cap_exceeded",
            "counts": {"selected_hosts": 1000, "observed_hosts": 1820},
            "source": "Cert Spotter",
        },
    )
    db_session.add(disc_res)
    db_session.flush()

    client = _make_client_for_user(fix["user_a"], db_session)
    response = client.get(f"/ui/orgs/{org_id}/scans/{scan_id}")
    assert response.status_code == 200
    html = response.text
    msg = (
        "Provider (Cert Spotter) limit reached and host cap applied "
        "(1000 selected from 1820 observed)."
    )
    assert msg in html


def test_scan_detail_legacy_report_notice(
    scan_detail_db_fixture, db_session: Session
):
    """Verify fallback notice for historical reports lacking truncation_reason."""
    fix = scan_detail_db_fixture
    scan_id = fix["scan_a"].id
    org_id = fix["org_a"].id

    stage_disc = ScanStage(
        scan_run_id=scan_id, stage="discover", status="succeeded", duration_ms=190
    )
    db_session.add(stage_disc)

    disc_res = ScanResult(
        scan_run_id=scan_id,
        stage="discover",
        report={
            "domain": "alpha.example.com",
            "truncated": True,
            "counts": {"total_discovered": 400},
            "source": "crt.sh",
        },
    )
    db_session.add(disc_res)
    db_session.flush()

    client = _make_client_for_user(fix["user_a"], db_session)
    response = client.get(f"/ui/orgs/{org_id}/scans/{scan_id}")
    assert response.status_code == 200
    html = response.text
    assert "Discovery results were truncated due to resource or provider limits." in html


def test_scan_detail_cross_tenant_isolation(
    scan_detail_db_fixture, db_session: Session
):
    """Verify strict multi-tenant boundary checks via require_org_role and get_scan_for_org."""
    fix = scan_detail_db_fixture
    org_a_id = fix["org_a"].id
    org_b_id = fix["org_b"].id
    scan_a_id = fix["scan_a"].id
    scan_b_id = fix["scan_b"].id

    # 1. User A cannot access Org B's scan: require_org_role denies non-member with 404
    client_a = _make_client_for_user(fix["user_a"], db_session)
    resp = client_a.get(f"/ui/orgs/{org_b_id}/scans/{scan_b_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Organization not found"

    # 2. User A requesting Org A route but passing Org B's scan_id:
    # get_scan_for_org filters (ScanRun.id == scan_id AND Domain.org_id == org_id) -> 404
    client_a = _make_client_for_user(fix["user_a"], db_session)
    resp = client_a.get(f"/ui/orgs/{org_a_id}/scans/{scan_b_id}")
    assert resp.status_code == 404
    assert f"Scan run with ID {scan_b_id} not found." in resp.json()["detail"]

    # 3. User B cannot access Org A's scan: require_org_role denies with 404
    client_b = _make_client_for_user(fix["user_b"], db_session)
    resp = client_b.get(f"/ui/orgs/{org_a_id}/scans/{scan_a_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Organization not found"

    # 4. User B requesting Org B route but passing Org A's scan_id:
    # get_scan_for_org filters (ScanRun.id == scan_id AND Domain.org_id == org_id) -> 404
    client_b = _make_client_for_user(fix["user_b"], db_session)
    resp = client_b.get(f"/ui/orgs/{org_b_id}/scans/{scan_a_id}")
    assert resp.status_code == 404
    assert f"Scan run with ID {scan_a_id} not found." in resp.json()["detail"]

    # 5. Outsider (non-member of both orgs) receives 404 on all routes
    client_outsider = _make_client_for_user(fix["user_outsider"], db_session)
    resp = client_outsider.get(f"/ui/orgs/{org_a_id}/scans/{scan_a_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Organization not found"

    resp = client_outsider.get(f"/ui/orgs/{org_b_id}/scans/{scan_b_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Organization not found"
