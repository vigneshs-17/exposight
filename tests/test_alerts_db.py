"""Database integration tests for alert notifications outbox and delivery."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from asm.admin import revoke_verification, suspend_user
from asm.api.routes import _notification_to_read
from asm.db.models import AlertNotification, Domain, Membership, Organization, ScanRun, User
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
        "portscan": {
            "results": [
                {
                    "subdomain": "api.alert-atomic.com",
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [5432],
                }
            ]
        },
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
        "inspect": {
            "results": [
                {
                    "subdomain": "alert-filter.com",
                    "status": "PROBED",
                    "headers": {
                        "present_headers": {"X-Content-Type-Options": "nosniff"},
                        "missing_headers": [],
                    },
                }
            ]
        },
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
                    "subdomain": "alert-filter.com",
                    "status": "PROBED",
                    "headers": {
                        "present_headers": {},
                        "missing_headers": ["X-Content-Type-Options"],
                    },
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
        "portscan": {
            "results": [
                {
                    "subdomain": "api.digest-err.com",
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [5432],
                }
            ]
        },
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
            alerts_enabled=True,
            alert_emails=["user@delivery-test.com", "fail@delivery-test.com"],
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
            alerts_enabled=True,
            alert_emails=[f"user{i}@concurrent-delivery.com" for i in range(4)],
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


@pytest.mark.db
def test_predelivery_authorization_recipient_removed_suppressed(
    db_engine, clean_db: None
) -> None:
    """Queued notification is suppressed when recipient is removed before delivery."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-r@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="recipient-rem.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["alice@recipient-rem.com", "bob@recipient-rem.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="alice@recipient-rem.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Separate session removes alice from alert_emails
    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        dom.alert_emails = ["bob@recipient-rem.com"]
        session.commit()

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "failed"
        assert row.attempts == 0  # Truthful count preserved: no send was attempted
        assert "Recipient is no longer configured" in row.last_error

    # Second pass does not retry
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()


@pytest.mark.db
def test_predelivery_authorization_alerts_disabled_suppressed(
    db_engine, clean_db: None
) -> None:
    """Queued notification is suppressed when domain alerts are disabled before delivery."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-d@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="alerts-dis.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@alerts-dis.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@alerts-dis.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Separate session disables alerts
    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        dom.alerts_enabled = False
        session.commit()

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "failed"
        assert row.attempts == 0
        assert "Domain alerts are disabled" in row.last_error


@pytest.mark.db
def test_predelivery_authorization_all_owners_suspended_suppressed(
    db_engine, clean_db: None
) -> None:
    """Queued notification is suppressed when all owners are suspended before delivery."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Suspended Org")
        session.add(org)
        session.flush()
        owner = User(id=uuid.uuid4(), email="sole-owner@susp.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="susp-owner.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["admin@susp-owner.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id
        owner_id = owner.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="admin@susp-owner.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Separate session suspends the sole owner
    with session_factory() as session:
        suspend_user(session, str(owner_id), reason="Non-payment")

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "failed"
        assert row.attempts == 0
        assert "All organization owners are suspended" in row.last_error


@pytest.mark.db
def test_predelivery_authorization_one_active_owner_remains_delivered(
    db_engine, clean_db: None
) -> None:
    """Notification delivers if at least one active owner remains."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Multi Owner Org")
        session.add(org)
        session.flush()
        owner1 = User(id=uuid.uuid4(), email="owner1@multi.com")
        owner2 = User(id=uuid.uuid4(), email="owner2@multi.com")
        session.add_all([owner1, owner2])
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner1.id, role="owner"))
        session.add(Membership(org_id=org.id, user_id=owner2.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="multi-owner.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@multi-owner.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id
        owner1_id = owner1.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@multi-owner.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Suspend owner1, leaving owner2 active
    with session_factory() as session:
        suspend_user(session, str(owner1_id), reason="Departed")

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "sent"
        assert row.attempts == 1


@pytest.mark.db
def test_predelivery_authorization_verification_revoked_suppressed(
    db_engine, clean_db: None
) -> None:
    """Scan-result notification is suppressed when verification is revoked before delivery."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-v@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="verif-rev.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@verif-rev.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@verif-rev.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Separate session revokes verification
    with session_factory() as session:
        revoke_verification(session, domain_id, reason="Ownership expired")

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        # Note: revoke_verification queues a verification-lapse alert; here we check
        # that the scan-result alert is suppressed and only the lapse alert sends.
        worker.deliver_pending_alerts()
        assert not any(
            "[Exposight] Alert" in call.kwargs.get("subject", "")
            for call in mock_send.call_args_list
        )

    with session_factory() as session:
        scan_alert_row = session.get(AlertNotification, notif_id)
        assert scan_alert_row.status == "failed"
        assert scan_alert_row.attempts == 0
        assert "Domain verification is inactive or expired" in scan_alert_row.last_error


@pytest.mark.db
def test_predelivery_authorization_verification_loss_notice_sends(
    db_engine, clean_db: None
) -> None:
    """Verification-loss notice delivers even when domain verification is inactive."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-vl@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="verif-loss.com",
            verification_status="pending",  # Inactive verification
            alerts_enabled=True,
            alert_emails=["admin@verif-loss.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        # Verification lapse notice: scan_run_id=None
        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="admin@verif-loss.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Details",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "sent"
        assert row.attempts == 1


@pytest.mark.db
def test_predelivery_authorization_viewer_privacy(
    db_engine, clean_db: None
) -> None:
    """Viewer responses redact recipient and suppression details in last_error."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        domain = Domain(
            org_id=org.id,
            name="viewer-privacy.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()

        n = AlertNotification(
            domain_id=domain.id,
            scan_run_id=None,
            recipient="secret@viewer-privacy.com",
            subject="[Exposight] Alert",
            body="Body",
            status="failed",
            attempts=0,
            last_error="Delivery suppressed: Recipient is no longer configured for domain alerts",
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        viewer_dto = _notification_to_read(row, role="viewer")
        admin_dto = _notification_to_read(row, role="admin")

        assert viewer_dto.recipient is None
        assert viewer_dto.last_error is None
        assert admin_dto.recipient == "secret@viewer-privacy.com"
        assert "Delivery suppressed" in admin_dto.last_error


@pytest.mark.db
def test_predelivery_malformed_notification_isolation(
    db_engine, clean_db: None
) -> None:
    """Malformed notification does not abort processing of other pending rows in batch."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-m@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="malformed-iso.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["injected\r\nattacker@malformed-iso.com", "good@malformed-iso.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        n_bad = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="injected\r\nattacker@malformed-iso.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Bad body",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=20),
        )
        n_good = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="good@malformed-iso.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Good body",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add_all([n_bad, n_good])
        session.commit()
        bad_id = n_bad.id
        good_id = n_good.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")

    delivered_recipients = []
    def mock_send(**kwargs):
        from asm.alerts.delivery import validate_email_address_header
        validate_email_address_header(kwargs["to_addr"])
        delivered_recipients.append(kwargs["to_addr"])

    with patch("asm.worker.worker.send_smtp_email", side_effect=mock_send):
        delivered = worker.deliver_pending_alerts(batch_limit=10)

    assert delivered == 1
    assert delivered_recipients == ["good@malformed-iso.com"]

    with session_factory() as session:
        bad_row = session.get(AlertNotification, bad_id)
        good_row = session.get(AlertNotification, good_id)
        assert bad_row.status == "pending"
        assert bad_row.attempts == 1
        assert "carriage return" in bad_row.last_error
        assert bad_row.next_attempt_at > datetime.now(UTC)
        assert good_row.status == "sent"
        assert good_row.attempts == 1


@pytest.mark.db
def test_predelivery_smtp_accept_crash_recovery_at_least_once(
    db_engine, clean_db: None
) -> None:
    """Worker crash after SMTP accept results in at-least-once re-delivery upon restart."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-c@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="crash-rec.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["admin@crash-rec.com"],
        )
        session.add(domain)
        session.flush()

        n = AlertNotification(
            domain_id=domain.id,
            scan_run_id=None,
            recipient="admin@crash-rec.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Crash body",
            status="pending",
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    w1 = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    def crash_after_send(**kwargs):
        raise KeyboardInterrupt("Simulated sudden worker crash / SIGKILL")

    with patch("asm.worker.worker.send_smtp_email", side_effect=crash_after_send):
        try:
            w1.deliver_pending_alerts()
        except KeyboardInterrupt:
            pass

    # Inspect DB after crash: transaction rolled back
    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "pending"
        assert row.attempts == 0

    # Second worker run restarts and delivers (at-least-once delivery)
    w2 = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = w2.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "sent"
        assert row.attempts == 1


@pytest.mark.db
def test_predelivery_authorization_verification_expires_suppressed(
    db_engine, clean_db: None
) -> None:
    """Scan notification is suppressed when verification_expires_at lapses after queueing."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-exp@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="verif-exp.com",
            verification_status="verified",
            verification_expires_at=datetime.now(UTC) + timedelta(minutes=10),
            alerts_enabled=True,
            alert_emails=["ops@verif-exp.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@verif-exp.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Separate session updates verification_expires_at to the past
    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        dom.verification_expires_at = datetime.now(UTC) - timedelta(seconds=10)
        session.commit()

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "failed"
        assert row.attempts == 0
        assert "Domain verification is inactive or expired" in row.last_error


@pytest.mark.db
def test_predelivery_authorization_prior_attempts_preserved_on_suppression(
    db_engine, clean_db: None
) -> None:
    """A previously attempted notification keeps its truthful attempt count upon suppression."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-att@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="prior-att.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@prior-att.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        # Notification that already had 2 prior failed SMTP attempts
        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@prior-att.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=2,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    # Now domain alerts are disabled
    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        dom.alerts_enabled = False
        session.commit()

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "failed"
        # Truthful attempt count preserved: must still be 2, not 3 or 5!
        assert row.attempts == 2
        assert "Domain alerts are disabled" in row.last_error


@pytest.mark.db
def test_predelivery_authorization_verification_loss_still_obeys_shared_rules(
    db_engine, clean_db: None
) -> None:
    """Verification-loss notices still require enabled alerts, valid recipient, and active owner."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-vl-shared@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="vl-shared.com",
            verification_status="lapsed",
            alerts_enabled=True,
            alert_emails=["ops@vl-shared.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id
        owner_id = owner.id

        # 1. Verification-loss notice for removed recipient
        n_removed = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="departed@vl-shared.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Details",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        # 2. Verification-loss notice for valid recipient
        n_valid = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="ops@vl-shared.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Details",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add_all([n_removed, n_valid])
        session.commit()
        rem_id = n_removed.id
        val_id = n_valid.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")

    # Pass 1: removed recipient is suppressed, valid recipient is delivered
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1
        assert mock_send.call_args.kwargs["to_addr"] == "ops@vl-shared.com"

    with session_factory() as session:
        rem_row = session.get(AlertNotification, rem_id)
        val_row = session.get(AlertNotification, val_id)
        assert rem_row.status == "failed"
        assert rem_row.attempts == 0
        assert "Recipient is no longer configured" in rem_row.last_error
        assert val_row.status == "sent"

    # Pass 2: If all owners suspended, even valid verification-loss notice is suppressed
    with session_factory() as session:
        n_susp = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="ops@vl-shared.com",
            subject="Domain verification lapsed: monitoring paused",
            body="Details",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n_susp)
        session.commit()
        susp_id = n_susp.id

    with session_factory() as session:
        suspend_user(session, str(owner_id), reason="Non-payment")

    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        susp_row = session.get(AlertNotification, susp_id)
        assert susp_row.status == "failed"
        assert susp_row.attempts == 0
        assert "All organization owners are suspended" in susp_row.last_error


@pytest.mark.db
def test_predelivery_authorization_unknown_notification_type_denied_exemption(
    db_engine, clean_db: None
) -> None:
    """Unknown or misleading domain notifications do not receive the verification exemption."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-unk@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="unknown-type.com",
            verification_status="pending",  # Inactive verification
            alerts_enabled=True,
            alert_emails=["ops@unknown-type.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        # Misleading subject prefix
        n_misleading = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="ops@unknown-type.com",
            subject="Domain verification: 2 new open ports detected",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        # Unrelated domain-level alert
        n_unrelated = AlertNotification(
            domain_id=domain_id,
            scan_run_id=None,
            recipient="ops@unknown-type.com",
            subject="System maintenance advisory",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add_all([n_misleading, n_unrelated])
        session.commit()
        m_id = n_misleading.id
        u_id = n_unrelated.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 0
        mock_send.assert_not_called()

    with session_factory() as session:
        m_row = session.get(AlertNotification, m_id)
        u_row = session.get(AlertNotification, u_id)
        assert m_row.status == "failed"
        assert "Domain verification is inactive or expired" in m_row.last_error
        assert u_row.status == "failed"
        assert "Domain verification is inactive or expired" in u_row.last_error


@pytest.mark.db
def test_predelivery_authorization_fresh_domain_state_observed_within_batch(
    db_engine, clean_db: None
) -> None:
    """Fresh committed domain state is observed when multiple notifications are in one batch."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = _ensure_org(session)
        owner = User(id=uuid.uuid4(), email="owner-batch@test.com")
        session.add(owner)
        session.flush()
        session.add(Membership(org_id=org.id, user_id=owner.id, role="owner"))
        domain = Domain(
            org_id=org.id,
            name="batch-freshness.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["alice@batch-freshness.com", "bob@batch-freshness.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n1 = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="alice@batch-freshness.com",
            subject="[Exposight] Alert 1",
            body="Body 1",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=20),
        )
        n2 = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="bob@batch-freshness.com",
            subject="[Exposight] Alert 2",
            body="Body 2",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add_all([n1, n2])
        session.commit()
        n1_id = n1.id
        n2_id = n2.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")

    delivered_recipients = []
    def send_and_mutate_domain(**kwargs):
        delivered_recipients.append(kwargs["to_addr"])
        # While n1 is delivering, a separate session removes bob from domain.alert_emails
        with session_factory() as mut_session:
            d = mut_session.get(Domain, domain_id)
            d.alert_emails = ["alice@batch-freshness.com"]
            mut_session.commit()

    with patch("asm.worker.worker.send_smtp_email", side_effect=send_and_mutate_domain):
        delivered = worker.deliver_pending_alerts(batch_limit=10)

    # In the same batch call, n1 delivered and n2 observed the mutation and was suppressed!
    assert delivered == 1
    assert delivered_recipients == ["alice@batch-freshness.com"]

    with session_factory() as session:
        r1 = session.get(AlertNotification, n1_id)
        r2 = session.get(AlertNotification, n2_id)
        assert r1.status == "sent"
        assert r2.status == "failed"
        assert "Recipient is no longer configured" in r2.last_error


@pytest.mark.db
def test_predelivery_authorization_zero_owner_org_delivers(
    db_engine, clean_db: None
) -> None:
    """An organization with zero owners is not treated as suspended and allows delivery."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Zero Owner Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="zero-owner.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@zero-owner.com"],
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.flush()

        n = AlertNotification(
            domain_id=domain_id,
            scan_run_id=run.id,
            recipient="ops@zero-owner.com",
            subject="[Exposight] Alert",
            body="Body",
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=10),
        )
        session.add(n)
        session.commit()
        notif_id = n.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        row = session.get(AlertNotification, notif_id)
        assert row.status == "sent"
