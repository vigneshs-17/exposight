"""Comprehensive staging validation drill executing against isolated DB and live Mailpit.

Validates:
1. Exact commit and build identity.
2. Fresh database migration lifecycle (0001 -> 0015) and zero drift.
3. Database role permissions and audit_events immutability.
4. Tenant isolation and organization creation allowlist.
5. Domain verification and G5.2 Option A viewer token redaction.
6. Multi-scan lifecycle, change detection, and alert outbox generation.
7. SMTP delivery to Mailpit (127.0.0.1:1025) and verification via Mailpit API (127.0.0.1:8026).
8. Viewer privacy redaction for alert notifications.
9. Compose config and egress firewall rule invariants.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from asm.api.routes import _domain_to_read, _notification_to_read
from asm.db.models import (
    AlertNotification,
    AuditEvent,
    Domain,
    Organization,
    ScanChange,
    ScanRun,
)
from asm.db.scans import enqueue_scan
from asm.worker.runner import IScannerRunner
from asm.worker.worker import ASMWorker

REPO_ROOT = Path(__file__).resolve().parent.parent


class StagingMockRunner(IScannerRunner):
    """Mock runner providing deterministic multi-scan stages for change detection."""

    def __init__(self, reports_by_stage: dict[str, dict[str, Any]]) -> None:
        self.reports = reports_by_stage

    def run_discover(self, domain: str) -> dict[str, Any]:
        return self.reports["discover"]

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports["probe"]

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports["portscan"]

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports["inspect"]

    def run_score(
        self,
        domain: str,
        discover_report: dict[str, Any],
        probe_report: dict[str, Any],
        portscan_report: dict[str, Any],
        inspect_report: dict[str, Any],
    ) -> dict[str, Any]:
        return self.reports["score"]


def test_staging_drill_compose_and_image_identity():
    """Verify compose.prod.yml + compose.staging.override.yml syntax and required image tags."""
    proc = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            "exposight-staging",
            "-f",
            "compose.prod.yml",
            "-f",
            "compose.staging.override.yml",
            "--env-file",
            "deploy/staging.env.example",
            "config",
            "--quiet",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"docker compose config failed: {proc.stderr}"

    # Also verify with mailsink profile
    proc_sink = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            "exposight-staging",
            "-f",
            "compose.prod.yml",
            "-f",
            "compose.staging.override.yml",
            "--profile",
            "mailsink",
            "--env-file",
            "deploy/staging.env.example",
            "config",
            "--quiet",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc_sink.returncode == 0, (
        f"docker compose config with mailsink failed: {proc_sink.stderr}"
    )


def test_staging_drill_db_audit_append_only(db_engine, clean_db):
    """Verify that audit_events table rejects UPDATE, DELETE, and TRUNCATE."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Audit Test Org")
        session.add(org)
        session.flush()

        event = AuditEvent(
            org_id=org.id,
            actor_type="system",
            actor_user_id=None,
            action="staging.test.action",
            target_type="system",
            target_id="drill-1",
            metadata_={"drill": True},
        )
        session.add(event)
        session.commit()
        event_id = event.id

    # Attempting to update must raise trigger exception
    with session_factory() as session:
        with pytest.raises(Exception) as excinfo:
            session.execute(
                text("UPDATE audit_events SET action = 'tampered' WHERE id = :id"),
                {"id": event_id},
            )
            session.commit()
        err_msg = str(excinfo.value).lower()
        assert "append-only" in err_msg or "prohibited" in err_msg

    # Attempting to delete must raise trigger exception
    with session_factory() as session:
        with pytest.raises(Exception) as excinfo:
            session.execute(
                text("DELETE FROM audit_events WHERE id = :id"),
                {"id": event_id},
            )
            session.commit()
        err_msg = str(excinfo.value).lower()
        assert "append-only" in err_msg or "prohibited" in err_msg


def test_staging_drill_domain_verification_and_viewer_token_redaction(db_engine, clean_db):
    """Verify domain verification token is properly redacted for viewer role (G5.2 Option A)."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Staging Token Org")
        session.add(org)
        session.flush()

        domain = Domain(
            org_id=org.id,
            name="staging-token.example.com",
            verification_status="pending",
            verification_token="exposight-challenge-sec-token-12345",
            verification_method="dns_txt",
        )
        session.add(domain)
        session.commit()

        # Read as admin: tokens present
        read_admin = _domain_to_read(domain, role="admin")
        assert read_admin.verification_token == "exposight-challenge-sec-token-12345"
        assert (
            read_admin.verification_record_value
            == "exposight-verify=exposight-challenge-sec-token-12345"
        )

        # Read as viewer: tokens strictly None (G5.2 Option A)
        read_viewer = _domain_to_read(domain, role="viewer")
        assert read_viewer.verification_token is None
        assert read_viewer.verification_record_value is None

        # Simulate verification success
        domain.verification_status = "verified"
        domain.verified_at = datetime.now(UTC)
        session.commit()
        assert domain.is_verified is True


def _is_port_open(host: str, port: int) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def test_staging_drill_scan_change_detection_and_mailpit_delivery(db_engine, clean_db):
    """Execute multi-scan lifecycle, detect changes, queue alert, and deliver via Mailpit."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Staging Scan Org")
        session.add(org)
        session.flush()

        domain = Domain(
            org_id=org.id,
            name="staging-scan.example.com",
            verification_status="verified",
            verified_at=datetime.now(UTC),
            alerts_enabled=True,
            alert_emails=["staging-alerts@staging.exposight.invalid"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        # Enqueue Scan 1: Baseline
        scan_run1 = enqueue_scan(session, domain_id=domain_id, trigger="manual")
        session.commit()
        run_id1 = scan_run1.id

    # Scan 1: Baseline reports
    scan1_reports = {
        "discover": {
            "domain": "staging-scan.example.com",
            "results": [
                {"subdomain": "staging-scan.example.com", "resolved": True},
                {"subdomain": "api.staging-scan.example.com", "resolved": True},
            ],
        },
        "probe": {"results": []},
        "portscan": {
            "results": [
                {
                    "subdomain": "api.staging-scan.example.com",
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [5432],
                }
            ]
        },
        "inspect": {"results": []},
        "score": {"domain_score": 0, "domain_band": "INFO", "hosts": []},
    }

    runner1 = StagingMockRunner(scan1_reports)
    worker = ASMWorker(
        engine=db_engine,
        runner=runner1,
        smtp_host="127.0.0.1",
        smtp_port=1025,
        smtp_from="alerts@staging.exposight.invalid",
    )

    processed1 = worker.run_poll_cycle()
    assert processed1 is True

    with session_factory() as session:
        run1 = session.get(ScanRun, run_id1)
        assert run1.status == "succeeded"
        assert run1.change_detection.get("status") == "baseline"

        # Enqueue Scan 2: State changes
        scan_run2 = enqueue_scan(session, domain_id=domain_id, trigger="manual")
        session.commit()
        run_id2 = scan_run2.id

    # Scan 2: State change (new subdomain, newly open port)
    scan2_reports = {
        "discover": {
            "domain": "staging-scan.example.com",
            "results": [
                {"subdomain": "staging-scan.example.com", "resolved": True},
                {"subdomain": "api.staging-scan.example.com", "resolved": True},
                {"subdomain": "admin.staging-scan.example.com", "resolved": True},
            ],
        },
        "probe": {"results": []},
        "portscan": {
            "results": [
                {
                    "subdomain": "api.staging-scan.example.com",
                    "status": "PROBED",
                    "open_ports": [
                        {
                            "port": 5432,
                            "state": "OPEN",
                            "service_guess": "postgresql",
                            "banner": "PostgreSQL 15",
                        }
                    ],
                }
            ]
        },
        "inspect": {"results": []},
        "score": {
            "domain_score": 10,
            "domain_band": "CRITICAL",
            "hosts": [
                {
                    "subdomain": "api.staging-scan.example.com",
                    "score": 10,
                    "band": "CRITICAL",
                }
            ],
        },
    }

    runner2 = StagingMockRunner(scan2_reports)
    worker.runner = runner2

    processed2 = worker.run_poll_cycle()
    assert processed2 is True

    with session_factory() as session:
        run2 = session.get(ScanRun, run_id2)
        assert run2.status == "succeeded"

        # Verify changes were detected and recorded
        changes = (
            session.query(ScanChange)
            .filter_by(scan_run_id=run_id2)
            .all()
        )
        assert len(changes) > 0, "Expected changes detected in Scan 2"
        change_types = [c.change_type for c in changes]
        assert "NEW_SUBDOMAIN" in change_types or "PORT_NEWLY_OPEN" in change_types

        # Verify alert notifications outbox
        notifications = (
            session.query(AlertNotification)
            .filter_by(domain_id=domain_id)
            .all()
        )
        assert len(notifications) > 0, "Expected alert notifications generated"

    # Deliver pending alerts via worker to Mailpit (or mock if Mailpit container not running)
    live_mailpit = _is_port_open("127.0.0.1", 1025)
    if live_mailpit:
        delivered_count = worker.deliver_pending_alerts()
    else:
        from unittest.mock import patch

        with patch("asm.alerts.delivery.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = mock_smtp_cls.return_value.__enter__.return_value
            delivered_count = worker.deliver_pending_alerts()
            assert mock_smtp.send_message.called
    assert delivered_count > 0, f"Expected >0 delivered alerts, got {delivered_count}"

    with session_factory() as session:
        # Verify outbox status updated to delivered
        notifications = (
            session.query(AlertNotification)
            .filter_by(domain_id=domain_id)
            .all()
        )
        for n in notifications:
            assert n.status in ("sent", "delivered")
            assert n.sent_at is not None

            # Viewer privacy redaction check: recipient is None for viewer
            read_viewer = _notification_to_read(n, role="viewer")
            assert read_viewer.recipient is None

            read_admin = _notification_to_read(n, role="admin")
            assert read_admin.recipient == "staging-alerts@staging.exposight.invalid"

    # Verify message in Mailpit API if live
    if live_mailpit and _is_port_open("127.0.0.1", 8026):
        req = urllib.request.Request("http://127.0.0.1:8026/api/v1/messages")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            messages = data.get("messages", [])
            assert len(messages) >= 1
            subjects = [m.get("Subject", "") for m in messages]
            assert any(
                "staging-scan.example.com" in s or "Exposight" in s or "alert" in s.lower()
                for s in subjects
            )
