"""Database and worker integration tests for Exposight change detection (v2.3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asm.db.models import Domain, Organization, ScanChange, ScanResult, ScanRun, ScanStage
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


class MultiScanReportRunner:
    """Mock runner supplying full stage report dictionaries indexed by sequential scan execution."""

    def __init__(self, reports_list: list[dict[str, Any]]) -> None:
        self.reports_list = reports_list
        self.scan_idx = 0
        self._current_report: dict[str, Any] = {}

    def run_discover(self, domain: str) -> dict[str, Any]:
        self._current_report = self.reports_list[self.scan_idx]
        self.scan_idx += 1
        return self._current_report["discover"]

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._current_report["probe"]

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._current_report["portscan"]

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self._current_report["inspect"]

    def run_score(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        return self._current_report["score"]


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


def test_worker_multi_scan_history_window_and_domain_isolation(clean_db, db_engine):
    """Worker query strictly selects the latest 3 prior succeeded scans for target domain,
    excluding interleaved other-domain scans, failed scans, and scans with id > current."""
    with Session(db_engine) as session:
        org = _ensure_org(session)
        target_domain = Domain(
            org_id=org.id, name="target-domain.example.com", verification_status="verified"
        )
        other_domain = Domain(
            org_id=org.id, name="other-domain.example.com", verification_status="verified"
        )
        session.add_all([target_domain, other_domain])
        session.flush()

        # 1. Target domain scan 1 (succeeded - older than 3-scan window)
        r1 = ScanRun(domain_id=target_domain.id, status="succeeded")
        # 2. Target domain scan 2 (succeeded - 3rd newest baseline)
        r2 = ScanRun(domain_id=target_domain.id, status="succeeded")
        session.add_all([r1, r2])
        session.flush()

        # 3. Interleaved other domain scan (succeeded - MUST be excluded)
        r_other = ScanRun(domain_id=other_domain.id, status="succeeded")
        session.add(r_other)
        session.flush()

        # 4. Target domain scan 3 (succeeded - 2nd newest baseline)
        r3 = ScanRun(domain_id=target_domain.id, status="succeeded")
        # 5. Target domain scan failed (failed - MUST be excluded)
        r_failed = ScanRun(domain_id=target_domain.id, status="failed")
        # 6. Target domain scan 4 (succeeded - 1st newest baseline)
        r4 = ScanRun(domain_id=target_domain.id, status="succeeded")
        session.add_all([r3, r_failed, r4])
        session.flush()

        # 7. Target domain current scan (queued)
        r_current = ScanRun(domain_id=target_domain.id, status="queued")
        session.add(r_current)
        session.flush()
        for st in ("discover", "probe", "portscan", "inspect", "score"):
            session.add(ScanStage(scan_run_id=r_current.id, stage=st, status="pending"))

        # 8. Target domain later scan (succeeded, id > r_current.id - MUST be excluded)
        r_later = ScanRun(domain_id=target_domain.id, status="succeeded")
        session.add(r_later)
        session.flush()

        # Add scan_results reports for all succeeded runs to verify ANY(:baseline_ids) retrieval
        for run_obj in (r1, r2, r_other, r3, r4, r_later):
            for st in ("discover", "probe", "portscan", "inspect", "score"):
                session.add(
                    ScanResult(
                        scan_run_id=run_obj.id,
                        stage=st,
                        report={"stage": st, "run_marker": run_obj.id},
                    )
                )
        session.commit()
        current_id = r_current.id
        expected_baseline_ids = [r4.id, r3.id, r2.id]
        excluded_ids = {r1.id, r_other.id, r_failed.id, r_later.id}

    # Dummy reports for the current queued run execution
    current_reports = {
        "discover": {"domain": "target-domain.example.com", "source": "crt.sh", "results": []},
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {"results": []},
        "score": {
            "domain": "target-domain.example.com",
            "domain_band": "LOW",
            "domain_score": 0,
            "generated_utc": "2026-10-01T08:00:00Z",
        },
    }
    runner = ConfigurableScannerRunner(lambda d, c: current_reports)
    worker = ASMWorker(db_engine, runner=runner)

    captured_call_args: dict[str, Any] = {}
    import asm.changes

    orig_detect = asm.changes.detect_changes

    def spy_detect_changes(*args, **kwargs):
        captured_call_args["historical_baselines"] = kwargs.get("historical_baselines")
        captured_call_args["baseline_scan_run_id"] = kwargs.get("baseline_scan_run_id")
        return orig_detect(*args, **kwargs)

    with patch("asm.changes.detect_changes", side_effect=spy_detect_changes):
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        fresh_run = session.get(ScanRun, current_id)
        assert fresh_run.status == "succeeded"
        assert fresh_run.change_detection["status"] == "computed"
        assert fresh_run.change_detection["baseline_scan_run_id"] == r4.id

    # Verify spy captured historical baselines
    hist = captured_call_args["historical_baselines"]
    assert hist is not None
    observed_ids = [b["scan_run_id"] for b in hist]
    # Strictly descending order of the latest 3 prior succeeded runs on target domain
    assert observed_ids == expected_baseline_ids

    # Verify excluded scans are absent
    for ex_id in excluded_ids:
        assert ex_id not in observed_ids

    # Verify reports were fetched from scan_results and unpacked correctly by stage
    for b_dict in hist:
        bid = b_dict["scan_run_id"]
        for st in ("discover", "probe", "portscan", "inspect", "score"):
            assert b_dict["reports"][st]["run_marker"] == bid


def test_worker_persists_distinct_baseline_scan_run_ids(clean_db, db_engine):
    """Changes emitted from the same scan persist different baseline_scan_run_id values
    corresponding to their historical observation origins in PostgreSQL."""
    domain_name = "multi-base.example.com"

    reports_seq = [
        # Scan 1: Presence of decommissioned, valid https, open 443, cert, HSTS present
        {
            "discover": {
                "domain": domain_name,
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": f"decommissioned.{domain_name}",
                        "status": "RESOLVED",
                        "resolved": True,
                    },
                    {"subdomain": f"api.{domain_name}", "status": "RESOLVED", "resolved": True},
                ],
            },
            "probe": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "reachable": True,
                        "http": {"reachable": True},
                        "https": {"reachable": True},
                    }
                ]
            },
            "portscan": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "open_ports": [{"port": 443, "state": "OPEN"}],
                        "closed_ports": [8443],
                    }
                ]
            },
            "inspect": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "cert": {
                            "expired": False,
                            "is_trusted": True,
                            "issuer": "CN=Let's Encrypt Authority X3",
                            "not_after": "2027-01-01T00:00:00Z",
                        },
                        "headers": {
                            "present_headers": {
                                "Strict-Transport-Security": "max-age=31536000"
                            },
                            "missing_headers": [],
                        },
                    }
                ]
            },
            "score": {
                "domain": domain_name,
                "domain_band": "LOW",
                "domain_score": 10,
                "generated_utc": "2026-10-01T08:00:00Z",
                "hosts": [{"subdomain": f"api.{domain_name}", "band": "LOW", "score": 10}],
            },
        },
        # Scan 2: Absence 1 for decommissioned, Failure 1 for HTTPS, Port 8443 closed, Inspect ERR
        {
            "discover": {
                "domain": domain_name,
                "source": "crt.sh",
                "results": [
                    {"subdomain": f"api.{domain_name}", "status": "RESOLVED", "resolved": True},
                ],
            },
            "probe": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "reachable": True,
                        "http": {"reachable": True},
                        "https": {
                            "reachable": False,
                            "error_type": "CONNECT_ERROR",
                            "error": "Connection refused",
                        },
                    }
                ]
            },
            "portscan": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "open_ports": [{"port": 443, "state": "OPEN"}],
                        "closed_ports": [8443],
                    }
                ]
            },
            "inspect": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "ERROR",
                        "cert": None,
                        "headers": None,
                    }
                ]
            },
            "score": {
                "domain": domain_name,
                "domain_band": "LOW",
                "domain_score": 10,
                "generated_utc": "2026-10-01T08:10:00Z",
                "hosts": [{"subdomain": f"api.{domain_name}", "band": "LOW", "score": 10}],
            },
        },
        # Scan 3: Absence 2 (removal), Failure 2 (loss), Port 8443 open, Cert & HSTS (anchored)
        {
            "discover": {
                "domain": domain_name,
                "source": "crt.sh",
                "results": [
                    {"subdomain": f"api.{domain_name}", "status": "RESOLVED", "resolved": True},
                ],
            },
            "probe": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "reachable": True,
                        "http": {"reachable": True},
                        "https": {
                            "reachable": False,
                            "error_type": "CONNECT_ERROR",
                            "error": "Connection refused",
                        },
                    }
                ]
            },
            "portscan": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "open_ports": [
                            {"port": 443, "state": "OPEN"},
                            {"port": 8443, "state": "OPEN", "service_guess": "https-alt"},
                        ],
                        "closed_ports": [],
                    }
                ]
            },
            "inspect": {
                "results": [
                    {
                        "subdomain": f"api.{domain_name}",
                        "status": "PROBED",
                        "cert": {
                            "expired": False,
                            "is_trusted": True,
                            "issuer": "CN=DigiCert Global Root G2",
                            "not_after": "2027-01-01T00:00:00Z",
                        },
                        "headers": {
                            "present_headers": {},
                            "missing_headers": ["Strict-Transport-Security"],
                        },
                    }
                ]
            },
            "score": {
                "domain": domain_name,
                "domain_band": "CRITICAL",
                "domain_score": 85,
                "generated_utc": "2026-10-01T08:20:00Z",
                "hosts": [{"subdomain": f"api.{domain_name}", "band": "CRITICAL", "score": 85}],
            },
        },
    ]

    runner = MultiScanReportRunner(reports_seq)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run1_id = create_domain_and_queue_scan(session, domain_name)

    # 1. Run scan 1 (baseline)
    assert worker.run_poll_cycle() is True

    # 2. Queue and run scan 2
    with Session(db_engine) as session:
        _, run2_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True

    # Scan 2 assertions: unconfirmed removal and loss must NOT be emitted
    with Session(db_engine) as session:
        s2_changes = session.query(ScanChange).filter_by(scan_run_id=run2_id).all()
        assert not any(c.change_type == "REMOVED_SUBDOMAIN" for c in s2_changes)
        assert not any(c.change_type == "HTTPS_LOST" for c in s2_changes)
        assert not any(c.change_type == "CERTIFICATE_CHANGED" for c in s2_changes)
        assert not any(c.change_type == "SECURITY_HEADER_REMOVED" for c in s2_changes)

    # 3. Queue and run scan 3
    with Session(db_engine) as session:
        _, run3_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True

    # Scan 3 assertions: distinct baseline_scan_run_id values committed to PostgreSQL
    with Session(db_engine) as session:
        fresh_run3 = session.get(ScanRun, run3_id)
        assert fresh_run3.status == "succeeded"
        assert fresh_run3.change_detection["status"] == "computed"
        # Primary baseline recorded on run summary is the immediate previous scan (run2)
        assert fresh_run3.change_detection["baseline_scan_run_id"] == run2_id

        changes = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run3_id)
            .order_by(ScanChange.id.asc())
            .all()
        )
        assert len(changes) > 0

        # Subdomain removal anchors to Scan 1 (last observed presence)
        removal = next(
            c for c in changes
            if c.change_type == "REMOVED_SUBDOMAIN"
            and c.asset == f"decommissioned.{domain_name}"
        )
        assert removal.baseline_scan_run_id == run1_id
        assert removal.evidence == "discover"

        # HTTPS lost anchors to Scan 1 (last observed reachability)
        https_lost = next(
            c for c in changes
            if c.change_type == "HTTPS_LOST"
            and c.asset == f"api.{domain_name}"
        )
        assert https_lost.baseline_scan_run_id == run1_id
        assert https_lost.evidence == "probe"

        # Certificate change anchors to Scan 1 (last valid cert inspection)
        cert_ch = next(
            c for c in changes
            if c.change_type == "CERTIFICATE_CHANGED"
            and c.asset == f"api.{domain_name}"
        )
        assert cert_ch.baseline_scan_run_id == run1_id
        assert cert_ch.evidence == "inspect"

        # Security header removal anchors to Scan 1 (last valid header inspection)
        header_rem = next(
            c for c in changes
            if c.change_type == "SECURITY_HEADER_REMOVED"
            and c.detail == "Strict-Transport-Security"
        )
        assert header_rem.baseline_scan_run_id == run1_id
        assert header_rem.evidence == "inspect"

        # Newly open port 8443 anchors to immediate baseline Scan 2
        port_open = next(
            c for c in changes
            if c.change_type == "PORT_NEWLY_OPEN"
            and c.detail == "8443"
        )
        assert port_open.baseline_scan_run_id == run2_id
        assert port_open.evidence == "portscan"

        # Risk band increase anchors to immediate baseline Scan 2
        band_change = next(
            c for c in changes
            if c.change_type == "DOMAIN_RISK_BAND_INCREASED"
        )
        assert band_change.baseline_scan_run_id == run2_id
        assert band_change.evidence == "score"

        # Verify all changes have valid foreign keys and matching domain_id
        for c in changes:
            assert c.domain_id == domain_id
            assert c.scan_run_id == run3_id
            assert c.baseline_scan_run_id in (run1_id, run2_id)


def test_worker_subdomain_removal_lifecycle_db(clean_db, db_engine):
    """Full database lifecycle for REMOVED_SUBDOMAIN:
    Scan 1 (Present) -> Scan 2 (Absent #1: no event) -> Scan 3 (Absent #2: emits REMOVED_SUBDOMAIN)
    -> Scan 4 (Absent #3: no duplicate event)."""
    domain_name = "removal-cycle.example.com"
    sub = f"temp.{domain_name}"
    stable_sub = f"stable.{domain_name}"

    def make_reports(variable_results):
        all_results = [
            {"subdomain": stable_sub, "status": "RESOLVED", "resolved": True}
        ] + variable_results
        return {
            "discover": {"domain": domain_name, "source": "crt.sh", "results": all_results},
            "probe": {"results": []},
            "portscan": {"results": []},
            "inspect": {"results": []},
            "score": {
                "domain": domain_name,
                "domain_band": "LOW",
                "domain_score": 0,
                "generated_utc": "2026-10-01T08:00:00Z",
            },
        }

    reports = [
        make_reports([{"subdomain": sub, "status": "RESOLVED", "resolved": True}]),
        make_reports([]),
        make_reports([]),
        make_reports([]),
    ]

    runner = MultiScanReportRunner(reports)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run1_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True

    # Scan 2: 1st absence
    with Session(db_engine) as session:
        _, run2_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        count2 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run2_id, change_type="REMOVED_SUBDOMAIN")
            .count()
        )
        assert count2 == 0

    # Scan 3: 2nd absence -> exactly 1 removal change
    with Session(db_engine) as session:
        _, run3_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        ch3 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run3_id, change_type="REMOVED_SUBDOMAIN")
            .all()
        )
        assert len(ch3) == 1
        assert ch3[0].asset == sub
        assert ch3[0].baseline_scan_run_id == run1_id

    # Scan 4: 3rd absence -> no duplicate removal
    with Session(db_engine) as session:
        _, run4_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        count4 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run4_id, change_type="REMOVED_SUBDOMAIN")
            .count()
        )
        assert count4 == 0


def test_worker_https_lost_lifecycle_db(clean_db, db_engine):
    """Full database lifecycle for HTTPS_LOST:
    Scan 1 (Success) -> Scan 2 (Failure #1: no event) -> Scan 3 (Failure #2: emits HTTPS_LOST)
    -> Scan 4 (Failure #3: no duplicate event)."""
    domain_name = "https-lost-cycle.example.com"
    host = f"api.{domain_name}"

    def make_probe_reports(https_reachable: bool):
        probe_res = {
            "subdomain": host,
            "status": "PROBED",
            "reachable": True,
            "http": {"reachable": True},
            "https": (
                {"reachable": True}
                if https_reachable
                else {
                    "reachable": False,
                    "error_type": "CONNECT_ERROR",
                    "error": "Connection refused",
                }
            ),
        }
        return {
            "discover": {
                "domain": domain_name,
                "source": "crt.sh",
                "results": [{"subdomain": host, "status": "RESOLVED", "resolved": True}],
            },
            "probe": {"results": [probe_res]},
            "portscan": {"results": []},
            "inspect": {"results": []},
            "score": {
                "domain": domain_name,
                "domain_band": "LOW",
                "domain_score": 0,
                "generated_utc": "2026-10-01T08:00:00Z",
            },
        }

    reports = [
        make_probe_reports(True),   # Scan 1: Reachable
        make_probe_reports(False),  # Scan 2: Unreachable #1
        make_probe_reports(False),  # Scan 3: Unreachable #2
        make_probe_reports(False),  # Scan 4: Unreachable #3
    ]

    runner = MultiScanReportRunner(reports)
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        domain_id, run1_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True

    # Scan 2: 1st failure
    with Session(db_engine) as session:
        _, run2_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        count2 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run2_id, change_type="HTTPS_LOST")
            .count()
        )
        assert count2 == 0

    # Scan 3: 2nd failure -> exactly 1 HTTPS_LOST change
    with Session(db_engine) as session:
        _, run3_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        ch3 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run3_id, change_type="HTTPS_LOST")
            .all()
        )
        assert len(ch3) == 1
        assert ch3[0].asset == host
        assert ch3[0].baseline_scan_run_id == run1_id

    # Scan 4: 3rd failure -> no duplicate HTTPS_LOST
    with Session(db_engine) as session:
        _, run4_id = create_domain_and_queue_scan(session, domain_name)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        count4 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run4_id, change_type="HTTPS_LOST")
            .count()
        )
        assert count4 == 0
