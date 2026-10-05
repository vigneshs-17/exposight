"""Database integration tests for alert notifications outbox and delivery."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from asm.db.models import AlertNotification, Domain, Organization, ScanRun
from asm.db.scans import enqueue_scan
from asm.worker.runner import IScannerRunner
from asm.worker.worker import ASMWorker


def _ensure_org(session) -> Organization:
    org = session.query(Organization).first()
    if not org:
        org = Organization(name="Alerts DB Test Org")
        session.add(org)
        session.flush()
    return org


class MockScannerRunner(IScannerRunner):
    """Mock scanner runner supplying predetermined stage reports."""

    def __init__(self, reports_by_stage: dict[str, dict[str, Any]]) -> None:
        self.reports_by_stage = reports_by_stage

    def run_discover(self, domain: str) -> dict[str, Any]:
        return self.reports_by_stage["discover"]

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports_by_stage["probe"]

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports_by_stage["portscan"]

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return self.reports_by_stage["inspect"]

    def run_score(
        self,
        domain: str,
        discover_report: dict[str, Any],
        probe_report: dict[str, Any] | None,
        portscan_report: dict[str, Any] | None,
        inspect_report: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return self.reports_by_stage["score"]


@pytest.mark.db
def test_outbox_written_atomically_in_fenced_transaction(
    db_engine, clean_db: None
) -> None:
    """Outbox rows are created in the same fenced transaction that stores changes."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="alert-atomic.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["sec@alert-atomic.com", "ops@alert-atomic.com"],
            alert_min_severity="MEDIUM",
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        # Scan 1: Baseline
        run1 = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        run1_id = run1.id

    # Run scan 1 (baseline)
    base_reports = {
        "discover": {
            "domain": "alert-atomic.com",
            "results": [{"subdomain": "api.alert-atomic.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {"results": []},
        "score": {"domain_score": 0, "domain_band": "INFO", "hosts": []},
    }
    worker1 = ASMWorker(engine=db_engine, runner=MockScannerRunner(base_reports))
    worker1.run_poll_cycle()

    # Verify run 1 succeeded and produced 0 alerts (baseline)
    with session_factory() as session:
        r1 = session.get(ScanRun, run1_id)
        assert r1.status == "succeeded"
        assert r1.change_detection["status"] == "baseline"
        alerts1 = session.scalars(
            select(AlertNotification).where(AlertNotification.scan_run_id == run1_id)
        ).all()
        assert len(alerts1) == 0

    # Scan 2: New exposed database port (CRITICAL exposure change)
    with session_factory() as session:
        run2 = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        run2_id = run2.id

    new_reports = {
        "discover": {
            "domain": "alert-atomic.com",
            "results": [{"subdomain": "api.alert-atomic.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {
            "results": [
                {
                    "subdomain": "api.alert-atomic.com",
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
            "hosts": [{"subdomain": "api.alert-atomic.com", "score": 10, "band": "CRITICAL"}],
        },
    }
    worker2 = ASMWorker(engine=db_engine, runner=MockScannerRunner(new_reports))
    worker2.run_poll_cycle()

    # Verify run 2 succeeded, change detection computed, and 2 outbox rows written
    with session_factory() as session:
        r2 = session.get(ScanRun, run2_id)
        assert r2.status == "succeeded"
        assert r2.change_detection["status"] == "computed"
        assert r2.change_detection["counts"]["critical"] >= 1

        alerts2 = session.scalars(
            select(AlertNotification)
            .where(AlertNotification.scan_run_id == run2_id)
            .order_by(AlertNotification.recipient.asc())
        ).all()
        assert len(alerts2) == 2
        assert alerts2[0].recipient == "ops@alert-atomic.com"
        assert alerts2[0].status == "pending"
        assert alerts2[0].attempts == 0
        assert "[Exposight] CRITICAL:" in alerts2[0].subject
        assert alerts2[1].recipient == "sec@alert-atomic.com"
        assert alerts2[1].status == "pending"


@pytest.mark.db
def test_no_alert_for_summary_only_or_below_threshold(
    db_engine, clean_db: None
) -> None:
    """Changes below alert_min_severity or summary-only changes create no alert outbox rows."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="alert-filter.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@alert-filter.com"],
            alert_min_severity="HIGH",  # High threshold
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        # Baseline run
        enqueue_scan(session, domain_id, trigger="manual")
        session.commit()

    base_reports = {
        "discover": {
            "domain": "alert-filter.com",
            "results": [{"subdomain": "alert-filter.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {"results": []},
        "score": {"domain_score": 0, "domain_band": "INFO", "hosts": []},
    }
    w1 = ASMWorker(engine=db_engine, runner=MockScannerRunner(base_reports))
    w1.run_poll_cycle()

    # Scan 2: only introduces a LOW severity finding (e.g. missing MIME type header)
    with session_factory() as session:
        r2 = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        r2_id = r2.id

    new_reports = {
        "discover": {
            "domain": "alert-filter.com",
            "results": [{"subdomain": "alert-filter.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {
            "results": [
                {
                    "host": "alert-filter.com",
                    "http_status": 200,
                    "missing_headers": ["X-Content-Type-Options"],
                }
            ]
        },
        "score": {
            "domain_score": 1,
            "domain_band": "LOW",
            "hosts": [{"subdomain": "alert-filter.com", "score": 1, "band": "LOW"}],
        },
    }
    w2 = ASMWorker(engine=db_engine, runner=MockScannerRunner(new_reports))
    w2.run_poll_cycle()

    with session_factory() as session:
        r2_obj = session.get(ScanRun, r2_id)
        assert r2_obj.status == "succeeded"
        # Since the only exposure was LOW and threshold was HIGH, 0 alerts created
        alerts = session.scalars(
            select(AlertNotification).where(AlertNotification.scan_run_id == r2_id)
        ).all()
        assert len(alerts) == 0


@pytest.mark.db
def test_digest_builder_exception_leaves_run_succeeded_with_alert_error(
    db_engine, clean_db: None
) -> None:
    """An exception in digest building leaves run succeeded with alert_error and 0 outbox rows."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="digest-err.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@digest-err.com"],
            alert_min_severity="LOW",
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        enqueue_scan(session, domain_id, trigger="manual")
        session.commit()

    base_reports = {
        "discover": {
            "domain": "digest-err.com",
            "results": [{"subdomain": "api.digest-err.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {"results": []},
        "score": {"domain_score": 0, "domain_band": "INFO", "hosts": []},
    }
    w = ASMWorker(engine=db_engine, runner=MockScannerRunner(base_reports))
    w.run_poll_cycle()

    # Second scan with new open port
    with session_factory() as session:
        r2 = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        r2_id = r2.id

    new_reports = {
        "discover": {
            "domain": "digest-err.com",
            "results": [{"subdomain": "api.digest-err.com", "resolved": True}],
        },
        "probe": {"results": []},
        "portscan": {
            "results": [
                {
                    "subdomain": "api.digest-err.com",
                    "status": "PROBED",
                    "open_ports": [
                        {
                            "port": 5432,
                            "state": "OPEN",
                            "service_guess": "postgresql",
                            "banner": "Postgres",
                        }
                    ],
                }
            ]
        },
        "inspect": {"results": []},
        "score": {"domain_score": 10, "domain_band": "CRITICAL", "hosts": []},
    }

    # Patch build_alert_digest to raise an unexpected exception
    with patch(
        "asm.worker.worker.build_alert_digest",
        side_effect=RuntimeError("Template corruption explosion"),
    ):
        w2 = ASMWorker(engine=db_engine, runner=MockScannerRunner(new_reports))
        w2.run_poll_cycle()

    with session_factory() as session:
        r2_obj = session.get(ScanRun, r2_id)
        # Scan run still marked succeeded
        assert r2_obj.status == "succeeded"
        # Error recorded in change_detection summary under alert_error
        assert "Template corruption explosion" in r2_obj.change_detection["alert_error"]
        # 0 outbox rows written
        alerts = session.scalars(
            select(AlertNotification).where(AlertNotification.scan_run_id == r2_id)
        ).all()
        assert len(alerts) == 0


@pytest.mark.db
def test_uniqueness_per_recipient(db_engine, clean_db: None) -> None:
    """Duplicate outbox rows for same (scan_run_id, recipient) are rejected by constraint."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="uniq-test.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()

        run = enqueue_scan(session, domain.id, trigger="manual")
        session.flush()

        n1 = AlertNotification(
            domain_id=domain.id,
            scan_run_id=run.id,
            recipient="same@uniq-test.com",
            subject="Subj 1",
            body="Body 1",
        )
        session.add(n1)
        session.commit()

        # Second insert with identical run_id and recipient must violate constraint
        n2 = AlertNotification(
            domain_id=domain.id,
            scan_run_id=run.id,
            recipient="same@uniq-test.com",
            subject="Subj 2",
            body="Body 2",
        )
        session.add(n2)
        with pytest.raises(IntegrityError) as exc:
            session.commit()
        assert "uq_alert_notifications_run_recipient" in str(exc.value)


@pytest.mark.db
def test_worker_delivery_success_and_retry_backoff(
    db_engine, clean_db: None
) -> None:
    """Worker delivers alert, records sent_at, and handles retry backoff up to failed."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="delivery-test.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()
        run_id = run.id

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run_id,
            recipient="user@delivery-test.com",
            subject="[Exposight] HIGH: alert",
            body="Alert details",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")

    # 1. Delivery succeeds
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        updated = session.get(AlertNotification, notif_id)
        assert updated.status == "sent"
        assert updated.sent_at is not None
        assert updated.attempts == 1
        assert updated.last_error is None

    # 2. Test delivery failure and retry backoff
    with session_factory() as session:
        n_fail = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run_id,
            recipient="fail@delivery-test.com",
            subject="[ASM] Alert",
            body="Fail body",
            status="pending",
            attempts=0,
            max_attempts=5,
            next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add(n_fail)
        session.commit()
        fail_id = n_fail.id

    with patch(
        "asm.worker.worker.send_smtp_email",
        side_effect=ConnectionRefusedError("SMTP server down"),
    ):
        worker.deliver_pending_alerts()

    with session_factory() as session:
        f_row = session.get(AlertNotification, fail_id)
        assert f_row.status == "pending"
        assert f_row.attempts == 1
        assert "SMTP server down" in f_row.last_error
        # next_attempt_at pushed forward
        assert f_row.next_attempt_at > datetime.now(UTC)

        # Force attempts to 4 and make due again
        f_row.attempts = 4
        f_row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    # 5th attempt fails -> status = 'failed'
    with patch(
        "asm.worker.worker.send_smtp_email",
        side_effect=ConnectionRefusedError("SMTP server down"),
    ):
        worker.deliver_pending_alerts()

    with session_factory() as session:
        final_row = session.get(AlertNotification, fail_id)
        assert final_row.status == "failed"
        assert final_row.attempts == 5


@pytest.mark.db
def test_backoff_sql_executes_against_postgres(db_engine, clean_db: None) -> None:
    """Test directly that next_attempt_at = now() + make_interval(secs => :s) executes cleanly."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        res = session.execute(
            text("SELECT now() + make_interval(secs => :s) AS next_time"),
            {"s": 45},
        ).scalar()
        assert res is not None
        assert res > datetime.now(UTC)


@pytest.mark.db
def test_concurrent_workers_deliver_each_row_once(
    db_engine, clean_db: None
) -> None:
    """Concurrent workers with FOR UPDATE SKIP LOCKED deliver each alert notification once."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="concurrent-delivery.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()

        run = enqueue_scan(session, domain.id, trigger="manual")
        session.flush()

        # Create 4 pending alert notifications
        for i in range(4):
            n = AlertNotification(
                domain_id=domain.id,
                scan_run_id=run.id,
                recipient=f"user{i}@concurrent-delivery.com",
                subject="Alert",
                body="Body",
                status="pending",
                next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
            )
            session.add(n)
        session.commit()

    send_lock = threading.Lock()
    sent_recipients: list[str] = []

    def mock_send(**kwargs):
        with send_lock:
            sent_recipients.append(kwargs["to_addr"])

    # Run two workers concurrently in separate threads
    w1 = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    w2 = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")

    with patch("asm.worker.worker.send_smtp_email", side_effect=mock_send):
        t1 = threading.Thread(target=w1.deliver_pending_alerts, kwargs={"batch_limit": 4})
        t2 = threading.Thread(target=w2.deliver_pending_alerts, kwargs={"batch_limit": 4})
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    # All 4 sent, exactly once each (no duplicates)
    assert len(sent_recipients) == 4
    assert len(set(sent_recipients)) == 4

    with session_factory() as session:
        sent_rows = session.scalars(
            select(AlertNotification).where(AlertNotification.status == "sent")
        ).all()
        assert len(sent_rows) == 4


@pytest.mark.db
def test_smtp_host_unset_leaves_rows_pending(db_engine, clean_db: None) -> None:
    """When SMTP_HOST is unset, deliver_pending_alerts returns 0 and leaves rows pending."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=_ensure_org(session).id,
            name="unset-smtp.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()

        run = enqueue_scan(session, domain.id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain.id,
            scan_run_id=run.id,
            recipient="user@unset-smtp.com",
            subject="Alert",
            body="Body",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    worker = ASMWorker(engine=db_engine, smtp_host=None)
    delivered = worker.deliver_pending_alerts()
    assert delivered == 0

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "pending"
        assert row.attempts == 0
