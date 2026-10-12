from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.main import app
from asm.db.models import Domain, Organization, ScanChange, ScanRun
from asm.db.session import get_db

pytestmark = pytest.mark.db


def test_health_endpoint_healthy(client: TestClient) -> None:
    """GET /health returns 200 and healthy database status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"


def test_health_endpoint_db_failure(client: TestClient) -> None:
    """GET /health returns 503 and clean JSON error without stack traces when DB is unreachable."""
    def _failing_db():
        failing_session = MagicMock()
        failing_session.execute.side_effect = RuntimeError("Connection refused")
        yield failing_session

    app.dependency_overrides[get_db] = _failing_db
    try:
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["status"] == "error"
        assert data["detail"]["database"] == "disconnected"
        assert "traceback" not in response.text
    finally:
        app.dependency_overrides.clear()


def test_create_domain_success(client: TestClient, test_org: Organization) -> None:
    """POST /orgs/{org_id}/domains registers a valid domain in pending verification state."""
    payload = {
        "name": "example.com",
    }
    response = client.post(f"/orgs/{test_org.id}/domains", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "example.com"
    assert data["verification_status"] == "pending"
    assert "verification_token" in data
    assert data["verification_record_name"] == "_exposight-challenge.example.com"
    assert data["verification_record_value"] == f"exposight-verify={data['verification_token']}"
    assert data["is_verified"] is False
    assert "id" in data
    assert "created_at" in data


def test_create_domain_normalizes_input(client: TestClient, test_org: Organization) -> None:
    """POST /orgs/{org_id}/domains normalizes input (strips scheme, port, path, casing)."""
    payload = {
        "name": "https://DEV.EXAMPLE.COM:8443/api/v1",
    }
    response = client.post(f"/orgs/{test_org.id}/domains", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "dev.example.com"


def test_create_domain_unauthorized_rejected(client: TestClient, test_org: Organization) -> None:
    """POST /orgs/{org_id}/domains creates pending domain and scans are rejected with 422."""
    payload = {
        "name": "unauthorized.com",
    }
    response = client.post(f"/orgs/{test_org.id}/domains", json=payload)
    assert response.status_code == 201
    domain_id = response.json()["id"]

    scan_resp = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/scans")
    assert scan_resp.status_code == 422
    assert "not verified" in scan_resp.text.lower()


def test_create_domain_invalid_syntax_rejected(client: TestClient, test_org: Organization) -> None:
    """POST /orgs/{org_id}/domains rejects IP addresses and invalid RFC domain labels with 422."""
    # Test IP address rejection
    ip_res = client.post(
        f"/orgs/{test_org.id}/domains", json={"name": "192.168.1.1"}
    )
    assert ip_res.status_code == 422
    assert "invalid domain" in ip_res.text.lower()

    # Test invalid hyphen placement
    hyphen_res = client.post(
        f"/orgs/{test_org.id}/domains", json={"name": "-invalid-.com"}
    )
    assert hyphen_res.status_code == 422
    assert "invalid domain" in hyphen_res.text.lower()


def test_create_domain_duplicate_conflict(client: TestClient, test_org: Organization) -> None:
    """POST /orgs/{org_id}/domains returns 409 Conflict when attempting duplicate registration."""
    payload = {"name": "unique.com"}
    first_res = client.post(f"/orgs/{test_org.id}/domains", json=payload)
    assert first_res.status_code == 201

    # Attempt duplicate registration
    dup_res = client.post(f"/orgs/{test_org.id}/domains", json=payload)
    assert dup_res.status_code == 409
    assert "already exists" in dup_res.text


def test_list_domains(client: TestClient, test_org: Organization) -> None:
    """GET /orgs/{org_id}/domains returns all registered domains in ascending ID order."""
    client.post(f"/orgs/{test_org.id}/domains", json={"name": "alpha.com"})
    client.post(f"/orgs/{test_org.id}/domains", json={"name": "beta.com"})

    response = client.get(f"/orgs/{test_org.id}/domains")
    assert response.status_code == 200
    data = response.json()
    names = [d["name"] for d in data]
    assert "alpha.com" in names
    assert "beta.com" in names


def test_get_domain_by_id_success(client: TestClient, test_org: Organization) -> None:
    """GET /orgs/{org_id}/domains/{id} returns domain details for an existing ID."""
    create_res = client.post(
        f"/orgs/{test_org.id}/domains", json={"name": "lookup.com"}
    )
    domain_id = create_res.json()["id"]

    get_res = client.get(f"/orgs/{test_org.id}/domains/{domain_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == domain_id
    assert get_res.json()["name"] == "lookup.com"


def test_get_domain_by_id_not_found(client: TestClient, test_org: Organization) -> None:
    """GET /orgs/{org_id}/domains/{id} returns 404 for a non-existent ID."""
    response = client.get(f"/orgs/{test_org.id}/domains/999999")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_test_safety_check_rejects_non_test_database() -> None:
    """Safety check fails if TEST_DATABASE_URL does not end with '_test'."""
    from tests.conftest import validate_test_database_url

    with pytest.raises(pytest.fail.Exception, match="Safety check failed"):
        validate_test_database_url("postgresql+psycopg://user:pass@localhost:5432/asm_prod")


def test_get_domain_changes_not_found(client: TestClient, test_org: Organization) -> None:
    """GET /orgs/{org_id}/domains/{id}/changes returns 404 for unknown domain."""
    response = client.get(f"/orgs/{test_org.id}/domains/999999/changes")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_get_scan_changes_not_found(client: TestClient, test_org: Organization) -> None:
    """GET /orgs/{org_id}/scans/{id}/changes returns 404 for unknown scan."""
    response = client.get(f"/orgs/{test_org.id}/scans/999999/changes")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_get_domain_changes_success_and_filters(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """GET /orgs/{org_id}/domains/{id}/changes returns newest-first changes with filtering."""
    domain = Domain(org_id=test_org.id, name="api-changes.com", verification_status="verified")
    db_session.add(domain)
    db_session.flush()

    run1 = ScanRun(domain_id=domain.id, status="succeeded")
    run2 = ScanRun(domain_id=domain.id, status="succeeded")
    db_session.add_all([run1, run2])
    db_session.flush()

    t_now = datetime.now(UTC)
    t_earlier = t_now - timedelta(hours=1)

    c1 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="PORT_NEWLY_OPEN",
        category="exposure",
        severity="CRITICAL",
        asset="api-changes.com",
        detail="3306",
        evidence="portscan",
        observed_at=t_earlier,
    )
    c2 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="SECURITY_HEADER_REMOVED",
        category="exposure",
        severity="LOW",
        asset="api-changes.com",
        detail="Strict-Transport-Security",
        evidence="inspect",
        observed_at=t_now,
    )
    db_session.add_all([c1, c2])
    db_session.flush()

    # 1. Fetch all changes (newest first)
    res = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/changes")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert data[0]["change_type"] == "SECURITY_HEADER_REMOVED"
    assert data[1]["change_type"] == "PORT_NEWLY_OPEN"

    # 2. Filter by severity
    res_crit = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/changes?severity=CRITICAL")
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    assert len(crit_data) == 1
    assert crit_data[0]["detail"] == "3306"

    # 3. Filter by since
    since_iso = (t_now - timedelta(minutes=30)).isoformat()
    res_since = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/changes?since={since_iso}")
    assert res_since.status_code == 200
    since_data = res_since.json()
    assert len(since_data) == 1
    assert since_data[0]["change_type"] == "SECURITY_HEADER_REMOVED"

    # 4. Pagination
    res_pag = client.get(f"/orgs/{test_org.id}/domains/{domain.id}/changes?limit=1&offset=1")
    assert res_pag.status_code == 200
    pag_data = res_pag.json()
    assert len(pag_data) == 1
    assert pag_data[0]["change_type"] == "PORT_NEWLY_OPEN"


def test_get_scan_changes_success(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """GET /orgs/{org_id}/scans/{id}/changes returns changes for a specific scan run."""
    domain = Domain(org_id=test_org.id, name="scan-changes.com", verification_status="verified")
    db_session.add(domain)
    db_session.flush()

    run1 = ScanRun(domain_id=domain.id, status="succeeded")
    run2 = ScanRun(domain_id=domain.id, status="succeeded")
    db_session.add_all([run1, run2])
    db_session.flush()

    c1 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="PORT_NEWLY_OPEN",
        category="exposure",
        severity="HIGH",
        asset="scan-changes.com",
        detail="3389",
        evidence="portscan",
        observed_at=datetime.now(UTC),
    )
    db_session.add(c1)
    db_session.flush()

    res = client.get(f"/orgs/{test_org.id}/scans/{run2.id}/changes")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["change_type"] == "PORT_NEWLY_OPEN"
    assert data[0]["detail"] == "3389"
    assert data[0]["scan_run_id"] == run2.id


def test_changes_endpoints_not_found_and_validation(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """GET /orgs/{org_id}/domains/{id}/changes and .../scans/{id}/changes return 404."""
    # 404 for unknown domain
    res_domain = client.get(f"/orgs/{test_org.id}/domains/999999/changes")
    assert res_domain.status_code == 404
    assert "Domain with ID 999999 not found" in res_domain.json()["detail"]

    # 404 for unknown scan
    res_scan = client.get(f"/orgs/{test_org.id}/scans/999999/changes")
    assert res_scan.status_code == 404
    assert "Scan run with ID 999999 not found" in res_scan.json()["detail"]

    # 422 for invalid since datetime
    domain = Domain(org_id=test_org.id, name="validation-test.com", verification_status="verified")
    db_session.add(domain)
    db_session.flush()

    res_invalid_since = client.get(
        f"/orgs/{test_org.id}/domains/{domain.id}/changes?since=not-a-datetime"
    )
    assert res_invalid_since.status_code == 422
    assert "Invalid ISO-8601" in res_invalid_since.json()["detail"]
