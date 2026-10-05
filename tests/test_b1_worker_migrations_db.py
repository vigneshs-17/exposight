"""v3.6b B-1: gate failure keeps finished stages; scan_runs index; lossy downgrades refused."""

import os
import subprocess
import sys
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from asm.db.models import ScanRun
from asm.worker.worker import ASMWorker
from tests.test_scan_lifecycle import MockScannerRunner, create_verified_domain

pytestmark = pytest.mark.db


class RevokeAfterDiscoverRunner(MockScannerRunner):
    """Discover succeeds, then the domain loses verification before the next stage starts."""

    def __init__(self, db_engine, domain_id: int) -> None:
        super().__init__()
        self.db_engine = db_engine
        self.domain_id = domain_id

    def run_discover(self, domain: str) -> dict[str, Any]:
        report = super().run_discover(domain)
        with self.db_engine.begin() as conn:
            conn.execute(
                text("UPDATE domains SET verification_status = 'pending' WHERE id = :id"),
                {"id": self.domain_id},
            )
        return report


def test_gate_failure_mid_scan_keeps_succeeded_stage(lifecycle_client, lifecycle_org, db_engine):
    client, org = lifecycle_client, lifecycle_org
    domain_id = create_verified_domain(client, org.id, "gate-midscan.example.com", db_engine)
    scan_id = client.post(f"/orgs/{org.id}/domains/{domain_id}/scans").json()["id"]

    worker = ASMWorker(engine=db_engine, runner=RevokeAfterDiscoverRunner(db_engine, domain_id))
    assert worker.run_poll_cycle() is True

    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"
        stages = dict(
            session.execute(
                text("SELECT stage, status FROM scan_stages WHERE scan_run_id = :id"),
                {"id": scan_id},
            ).all()
        )
        result_stages = {
            row[0]
            for row in session.execute(
                text("SELECT stage FROM scan_results WHERE scan_run_id = :id"), {"id": scan_id}
            ).all()
        }
    assert stages["discover"] == "succeeded"  # was overwritten to 'skipped' before B-1
    assert "discover" in result_stages
    for later in ("probe", "portscan", "inspect", "score"):
        assert stages[later] == "skipped"


@pytest.fixture
def scratch_db_url():
    """A throwaway database (name ends in _test) for running the real Alembic chain."""
    base = make_url(os.environ["TEST_DATABASE_URL"])
    name = "exposight_downgrade_guard_test"
    admin = sa.create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {name}"))
        conn.execute(text(f"CREATE DATABASE {name}"))
    try:
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {name}"))
        admin.dispose()


def _alembic(url: str, *args: str, allow: bool = False) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("ENVIRONMENT", "APP_DB_USER")}
    env["DATABASE_URL"] = url
    if allow:
        env["ALLOW_DATA_LOSS_DOWNGRADE"] = "1"
    else:
        env.pop("ALLOW_DATA_LOSS_DOWNGRADE", None)
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args], env=env, capture_output=True, text=True,
        timeout=120,
    )


def test_lossy_downgrades_refused_unless_explicitly_allowed(scratch_db_url):
    assert _alembic(scratch_db_url, "upgrade", "head").returncode == 0
    engine = sa.create_engine(scratch_db_url)
    with engine.begin() as conn:
        org_id = conn.execute(
            text("INSERT INTO organizations (name, created_at) VALUES ('O', now()) RETURNING id")
        ).scalar()
        conn.execute(
            text(
                "INSERT INTO domains (org_id, name, verification_status, verification_token, "
                "verification_method, consecutive_misses, alerts_enabled, alert_emails, "
                "alert_min_severity, created_at) VALUES (:o, 'kept.example.com', 'verified', "
                "'tok', 'dns_txt', 0, false, '[]', 'MEDIUM', now())"
            ),
            {"o": org_id},
        )
    engine.dispose()

    # Down to 0008 is fine (no guarded step yet).
    assert _alembic(scratch_db_url, "downgrade", "0008_domain_verification").returncode == 0

    refused_0008 = _alembic(scratch_db_url, "downgrade", "0007_tenant_isolation")
    assert refused_0008.returncode != 0
    assert "Refusing downgrade" in refused_0008.stderr
    assert "verification state" in refused_0008.stderr

    allowed_0008 = _alembic(scratch_db_url, "downgrade", "0007_tenant_isolation", allow=True)
    assert allowed_0008.returncode == 0, allowed_0008.stderr

    refused_0007 = _alembic(scratch_db_url, "downgrade", "0006_users_organizations_roles")
    assert refused_0007.returncode != 0
    assert "domains.org_id" in refused_0007.stderr

    allowed_0007 = _alembic(
        scratch_db_url, "downgrade", "0006_users_organizations_roles", allow=True
    )
    assert allowed_0007.returncode == 0, allowed_0007.stderr


def test_empty_database_downgrades_without_the_flag(scratch_db_url):
    assert _alembic(scratch_db_url, "upgrade", "head").returncode == 0

    # Migration 0012 creates the (domain_id, id DESC) index used by scan lists.
    engine = sa.create_engine(scratch_db_url)
    with engine.connect() as conn:
        indexdef = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = :n"),
            {"n": "ix_scan_runs_domain_id_id_desc"},
        ).scalar()
    engine.dispose()
    assert indexdef is not None and "(domain_id, id DESC)" in indexdef

    result = _alembic(scratch_db_url, "downgrade", "base")
    assert result.returncode == 0, result.stderr
