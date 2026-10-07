"""Database and worker integration tests for Exposight change detection (v2.3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asm.db.models import Domain, Organization, ScanChange, ScanRun, ScanStage
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


def _ensure_org(session: Session) -> Organization:
    org = session.query(Organization).first()
    if not org:
        org = Organization(name="Change Detection Test Org")
        session.add(org)
        session.flush()
    return org


def create_domain_and_queue_scan(session: Session, domain_name: str) -> tuple[int, int]:
    """Helper to register a domain, queue a scan run, and create its 5 pending stages."""
    domain = session.query(Domain).filter_by(name=domain_name).first()
    if not domain:
        org = _ensure_org(session)
        domain = Domain(org_id=org.id, name=domain_name, verification_status="verified")
        session.add(domain)
        session.flush()

    run = ScanRun(domain_id=domain.id, status="queued")
    session.add(run)
    session.flush()

    for st in ("discover", "probe", "portscan", "inspect", "score"):
        stage = ScanStage(scan_run_id=run.id, stage=st, status="pending")
        session.add(stage)

    session.commit()
    return domain.id, run.id


class ConfigurableScannerRunner:
    """Mock runner allowing dynamic stage reports per scan execution."""

    def __init__(self, reports_generator) -> None:
        self.reports_generator = reports_generator
        self.call_count = 0

    def _get_reports(self, domain: str) -> dict[str, dict[str, Any]]:
        self.call_count += 1
        return self.reports_generator(domain, self.call_count)

    def run_discover(self, domain: str) -> dict[str, Any]:
        return self._get_reports(domain)["discover"]

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._get_reports(domain)["probe"]

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._get_reports(domain)["portscan"]

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._get_reports(domain)["inspect"]

    def run_score(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        return self._get_reports(domain)["score"]


def test_first_scan_is_baseline_only(clean_db, db_engine):
    """The first succeeded scan for a domain records change_detection='baseline' and 0 changes."""
    def sample_reports(domain: str, call: int):
        return {
            "discover": {
                "domain": domain,
                "source": "crt.sh",
                "results": [{"subdomain": f"api.{domain}", "status": "RESOLVED", "resolved": True}],
            },
            "probe": {
                "results": [
                    {
                        "subdomain": f"api.{domain}",
                        "status": "PROBED",
                        "http": {"reachable": True},
                        "https": {"reachable": True},
                    }
                ]
            },
            "portscan": {
                "results": [
                    {
                        "subdomain": f"api.{domain}",
                        "status": "PROBED",
                        "open_ports": [{"port": 443, "state": "OPEN"}],
                    }
                ]
            },
            "inspect": {
                "results": [
                    {
                        "subdomain": f"api.{domain}",
                        "status": "PROBED",
                        "cert": {"expired": False, "is_trusted": True},
                        "headers": {
                            "present_headers": {
                                "Strict-Transport-Security": "max-age=31536000"
                            }
                        },
                    }
                ]
            },
            "score": {
                "domain": domain,
                "domain_band": "LOW",
                "domain_score": 10,
                "generated_utc": "2026-10-01T08:00:00Z",
                "hosts": [{"subdomain": f"api.{domain}", "band": "LOW", "score": 10}],
            },
        }

    runner = ConfigurableScannerRunner(sample_reports)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run_id = create_domain_and_queue_scan(session, "first-scan.example.com")

    # Run worker one job
    assert worker.run_poll_cycle() is True

    with Session(db_engine) as session:
        fresh_run = session.get(ScanRun, run_id)
        assert fresh_run.status == "succeeded"
        assert fresh_run.change_detection is not None
        assert fresh_run.change_detection["status"] == "baseline"
        assert fresh_run.change_detection["baseline_scan_run_id"] is None
        assert fresh_run.change_detection["removal_detection"] == "skipped"

        # No changes created for baseline scan
        changes_count = session.query(ScanChange).filter_by(scan_run_id=run_id).count()
        assert changes_count == 0


def test_second_scan_computes_and_persists_changes(clean_db, db_engine):
    """The second succeeded scan compares against baseline and persists structured changes."""
    def reports_gen(domain: str, call: int):
        # Call 1..5 for run 1; call 6..10 for run 2
        run_num = 1 if call <= 5 else 2
        if run_num == 1:
            return {
                "discover": {
                    "domain": domain,
                    "source": "crt.sh",
                    "results": [
                        {"subdomain": f"api.{domain}", "status": "RESOLVED", "resolved": True},
                    ],
                },
                "probe": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "http": {"reachable": True},
                            "https": {"reachable": True},
                        }
                    ]
                },
                "portscan": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "open_ports": [{"port": 443, "state": "OPEN"}],
                            "closed_ports": [3306],
                        }
                    ]
                },
                "inspect": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "cert": {"expired": False, "is_trusted": True},
                            "headers": {
                                "present_headers": {
                                    "Strict-Transport-Security": "max-age=31536000",
                                    "Content-Security-Policy": "default-src 'self'",
                                },
                                "missing_headers": [],
                            },
                        }
                    ]
                },
                "score": {
                    "domain": domain,
                    "domain_band": "LOW",
                    "domain_score": 10,
                    "generated_utc": "2026-10-01T08:00:00Z",
                    "hosts": [{"subdomain": f"api.{domain}", "band": "LOW", "score": 10}],
                },
            }
        else:
            # Second run has:
            # 1. new subdomain dev.domain
            # 2. open DB port 3306 with MySQL banner -> CRITICAL
            # 3. Content-Security-Policy removed -> LOW
            # 4. domain band elevated to CRITICAL
            return {
                "discover": {
                    "domain": domain,
                    "source": "crt.sh",
                    "results": [
                        {"subdomain": f"api.{domain}", "status": "RESOLVED", "resolved": True},
                        {"subdomain": f"dev.{domain}", "status": "RESOLVED", "resolved": True},
                    ],
                },
                "probe": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "http": {"reachable": True},
                            "https": {"reachable": True},
                        },
                        {
                            "subdomain": f"dev.{domain}",
                            "status": "PROBED",
                            "http": {"reachable": True},
                            "https": {"reachable": True},
                        },
                    ]
                },
                "portscan": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "open_ports": [
                                {"port": 443, "state": "OPEN"},
                                {
                                    "port": 3306,
                                    "state": "OPEN",
                                    "banner": "8.0.25-MySQL",
                                    "service_guess": "mysql",
                                },
                            ],
                            "closed_ports": [],
                        },
                        {
                            "subdomain": f"dev.{domain}",
                            "status": "PROBED",
                            "open_ports": [{"port": 80, "state": "OPEN"}],
                            "closed_ports": [],
                        },
                    ]
                },
                "inspect": {
                    "results": [
                        {
                            "subdomain": f"api.{domain}",
                            "status": "PROBED",
                            "cert": {"expired": False, "is_trusted": True},
                            "headers": {
                                "present_headers": {
                                    "Strict-Transport-Security": "max-age=31536000"
                                },
                                "missing_headers": ["Content-Security-Policy"],
                            },
                        },
                        {
                            "subdomain": f"dev.{domain}",
                            "status": "PROBED",
                            "cert": {"expired": False, "is_trusted": True},
                            "headers": {"present_headers": {}, "missing_headers": []},
                        },
                    ]
                },
                "score": {
                    "domain": domain,
                    "domain_band": "CRITICAL",
                    "domain_score": 85,
                    "generated_utc": "2026-10-01T08:30:00Z",
                    "hosts": [
                        {"subdomain": f"api.{domain}", "band": "CRITICAL", "score": 85},
                        {"subdomain": f"dev.{domain}", "band": "LOW", "score": 10},
                    ],
                },
            }

    runner = ConfigurableScannerRunner(reports_gen)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run1_id = create_domain_and_queue_scan(session, "multi-scan.example.com")

    # Execute first scan run
    worker.run_poll_cycle()

    # Queue second scan run
    with Session(db_engine) as session:
        _, run2_id = create_domain_and_queue_scan(session, "multi-scan.example.com")

    # Execute second scan run
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        fresh_run2 = session.get(ScanRun, run2_id)
        assert fresh_run2.status == "succeeded"
        assert fresh_run2.change_detection["status"] == "computed"
        assert fresh_run2.change_detection["baseline_scan_run_id"] == run1_id
        assert fresh_run2.change_detection["removal_detection"] == "performed"

        changes = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run2_id)
            .order_by(ScanChange.id.asc())
            .all()
        )
        assert len(changes) > 0

        # Verify DB port change
        db_change = next(
            c for c in changes if c.change_type == "PORT_NEWLY_OPEN" and c.detail == "3306"
        )
        assert db_change.severity == "CRITICAL"
        assert db_change.category == "exposure"
        assert db_change.evidence == "portscan"
        assert db_change.domain_id == domain_id
        assert db_change.baseline_scan_run_id == run1_id

        # Verify header removed change
        csp_change = next(
            c
            for c in changes
            if c.change_type == "SECURITY_HEADER_REMOVED"
            and c.detail == "Content-Security-Policy"
        )
        assert csp_change.severity == "LOW"
        assert csp_change.category == "exposure"
        assert csp_change.evidence == "inspect"

        # Verify new subdomain
        sub_change = next(
            c
            for c in changes
            if c.change_type == "NEW_SUBDOMAIN" and c.asset == "dev.multi-scan.example.com"
        )
        assert sub_change.severity == "INFO"
        assert sub_change.category == "exposure"
        assert sub_change.evidence == "discover"

        # Verify domain band increase
        domain_change = next(c for c in changes if c.change_type == "DOMAIN_RISK_BAND_INCREASED")
        assert domain_change.severity == "CRITICAL"
        assert domain_change.category == "summary"
        assert domain_change.evidence == "score"


def test_detection_exception_does_not_fail_scan(clean_db, db_engine):
    """If detection raises, scan still succeeds with change_detection='failed'."""
    def simple_reports(domain: str, call: int):
        return {
            "discover": {"domain": domain, "source": "crt.sh", "results": []},
            "probe": {"results": []},
            "portscan": {"results": []},
            "inspect": {"results": []},
            "score": {
                "domain": domain,
                "domain_band": "LOW",
                "domain_score": 0,
                "generated_utc": "2026-10-01T08:00:00Z",
            },
        }

    runner = ConfigurableScannerRunner(simple_reports)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run1_id = create_domain_and_queue_scan(session, "crash-diff.example.com")

    # Run 1 succeeds as baseline
    worker.run_poll_cycle()

    # Queue Run 2
    with Session(db_engine) as session:
        _, run2_id = create_domain_and_queue_scan(session, "crash-diff.example.com")

    # Patch detect_changes to raise
    with patch("asm.changes.detect_changes", side_effect=RuntimeError("Simulated diff failure")):
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        fresh_run2 = session.get(ScanRun, run2_id)
        # Scan run itself SUCCEEDED
        assert fresh_run2.status == "succeeded"
        # change_detection records failure
        assert fresh_run2.change_detection["status"] == "failed"
        assert "Simulated diff failure" in fresh_run2.change_detection["error"]
        # 0 changes persisted
        changes_count = session.query(ScanChange).filter_by(scan_run_id=run2_id).count()
        assert changes_count == 0


def test_baseline_query_ignores_later_scans(clean_db, db_engine):
    """Baseline query uses id < :current_id strictly, ignoring any scans with id > current."""
    with Session(db_engine) as session:
        org = _ensure_org(session)
        domain = Domain(
            org_id=org.id,
            name="order-check.example.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()

        # Run 1 (succeeded)
        run1 = ScanRun(domain_id=domain.id, status="succeeded")
        session.add(run1)
        session.flush()
        run1_id = run1.id

        # Run 2 (queued / to be executed)
        run2 = ScanRun(domain_id=domain.id, status="queued")
        session.add(run2)
        session.flush()
        run2_id = run2.id
        for st in ("discover", "probe", "portscan", "inspect", "score"):
            session.add(ScanStage(scan_run_id=run2.id, stage=st, status="pending"))

        # Run 3 (succeeded, id > run2)
        run3 = ScanRun(domain_id=domain.id, status="succeeded")
        session.add(run3)
        session.flush()
        run3_id = run3.id
        session.commit()

    def simple_reports(domain: str, call: int):
        return {
            "discover": {"domain": domain, "source": "crt.sh", "results": []},
            "probe": {"results": []},
            "portscan": {"results": []},
            "inspect": {"results": []},
            "score": {
                "domain": domain,
                "domain_band": "LOW",
                "domain_score": 0,
                "generated_utc": "2026-10-01T08:00:00Z",
            },
        }

    runner = ConfigurableScannerRunner(simple_reports)
    worker = ASMWorker(db_engine, runner=runner)

    # Worker executes run 2
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        fresh_run2 = session.get(ScanRun, run2_id)
        assert fresh_run2.status == "succeeded"
        # Baseline MUST be run 1 (strictly earlier), NOT run 3!
        assert fresh_run2.change_detection["baseline_scan_run_id"] == run1_id
        assert fresh_run2.change_detection["baseline_scan_run_id"] != run3_id


def test_unique_constraint_enforcement_on_scan_changes(clean_db, db_engine):
    """Insert of duplicate (scan_run_id, change_type, asset, detail) raises IntegrityError."""
    with Session(db_engine) as session:
        org = _ensure_org(session)
        domain = Domain(
            org_id=org.id,
            name="unique-test.example.com",
            verification_status="verified",
        )
        session.add(domain)
        session.commit()

        run1 = ScanRun(domain_id=domain.id, status="succeeded")
        run2 = ScanRun(domain_id=domain.id, status="succeeded")
        session.add_all([run1, run2])
        session.commit()

        now_dt = datetime.now(UTC)
        c1 = ScanChange(
            domain_id=domain.id,
            scan_run_id=run2.id,
            baseline_scan_run_id=run1.id,
            change_type="PORT_NEWLY_OPEN",
            category="exposure",
            severity="HIGH",
            asset="api.example.com",
            detail="3306",
            evidence="portscan",
            observed_at=now_dt,
        )
        session.add(c1)
        session.commit()

        # Duplicate (run2.id, PORT_NEWLY_OPEN, api.example.com, 3306)
        c2 = ScanChange(
            domain_id=domain.id,
            scan_run_id=run2.id,
            baseline_scan_run_id=run1.id,
            change_type="PORT_NEWLY_OPEN",
            category="exposure",
            severity="HIGH",
            asset="api.example.com",
            detail="3306",
            evidence="portscan",
            observed_at=now_dt,
        )
        session.add(c2)
        with pytest.raises(IntegrityError):
            session.commit()


def test_cascade_delete_on_scan_changes(clean_db, db_engine):
    """Deleting a ScanRun automatically deletes associated ScanChange records."""
    with Session(db_engine) as session:
        org = _ensure_org(session)
        domain = Domain(
            org_id=org.id,
            name="cascade-test.example.com",
            verification_status="verified",
        )
        session.add(domain)
        session.commit()

        run1 = ScanRun(domain_id=domain.id, status="succeeded")
        run2 = ScanRun(domain_id=domain.id, status="succeeded")
        session.add_all([run1, run2])
        session.commit()

        c1 = ScanChange(
            domain_id=domain.id,
            scan_run_id=run2.id,
            baseline_scan_run_id=run1.id,
            change_type="PORT_NEWLY_OPEN",
            category="exposure",
            severity="HIGH",
            asset="api.example.com",
            detail="3306",
            evidence="portscan",
            observed_at=datetime.now(UTC),
        )
        session.add(c1)
        session.commit()

        assert session.query(ScanChange).filter_by(scan_run_id=run2.id).count() == 1

        # Delete scan run 2
        session.delete(run2)
        session.commit()

        # ScanChange deleted by ON DELETE CASCADE
        assert session.query(ScanChange).filter_by(scan_run_id=run2.id).count() == 0
