"""Asynchronous background worker executing scan runs from PostgreSQL."""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import socket
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from asm.alerts.delivery import send_smtp_email
from asm.alerts.digest import build_alert_digest
from asm.alerts.rules import should_trigger_alerts
from asm.audit import record_event
from asm.db.models import Domain, ScanResult
from asm.db.scans import enqueue_scan
from asm.ratelimit import MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY
from asm.retention import purge_enabled, purge_expired
from asm.scan_common import sanitize_error_text
from asm.verification import (
    apply_check_outcome,
    check_dns_txt_verification,
    queue_domain_alert,
)
from asm.worker.exceptions import (
    EXPECTED_SCANNER_ERRORS,
    LostLeaseError,
    SecurityGateError,
)
from asm.worker.runner import DirectScannerRunner, IScannerRunner

logger = logging.getLogger("asm.worker")

ALL_STAGES = ("discover", "probe", "portscan", "inspect", "score")
PURGE_EVERY_S = 3600.0


class HeartbeatThread(threading.Thread):
    """Background thread renewing worker lease at fixed intervals using its own DB session."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        scan_run_id: int,
        claim_token: uuid.UUID,
        lease_duration: int,
        heartbeat_interval: float,
        lost_lease_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True, name=f"Heartbeat-{scan_run_id}")
        self.session_factory = session_factory
        self.scan_run_id = scan_run_id
        self.claim_token = claim_token
        self.lease_duration = lease_duration
        self.heartbeat_interval = heartbeat_interval
        self.lost_lease_event = lost_lease_event
        self.stop_requested = threading.Event()

    def run(self) -> None:
        logger.debug("Heartbeat thread started for scan_run_id=%d", self.scan_run_id)
        while not self.stop_requested.wait(self.heartbeat_interval):
            try:
                with self.session_factory() as session:
                    res = session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET lease_expires_at = now()
                                + CAST(:lease_duration || ' seconds' AS INTERVAL)
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": self.scan_run_id,
                            "lease_duration": self.lease_duration,
                            "token": self.claim_token,
                        },
                    )
                    session.commit()
                    if res.rowcount == 0:
                        logger.warning(
                            "Heartbeat found 0 rows updated for scan_run_id=%d (lease lost)",
                            self.scan_run_id,
                        )
                        self.lost_lease_event.set()
                        break
            except Exception as exc:
                logger.warning(
                    "Error executing heartbeat for scan_run_id=%d: %s",
                    self.scan_run_id,
                    exc,
                )

    def stop(self) -> None:
        self.stop_requested.set()


class ASMWorker:
    """Production-grade scan runner claiming jobs from PostgreSQL via SKIP LOCKED."""

    def __init__(
        self,
        engine: Engine | None = None,
        runner: IScannerRunner | None = None,
        worker_id: str | None = None,
        poll_interval: float = 3.0,
        lease_duration: int = 60,
        heartbeat_interval: float = 15.0,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_from: str | None = None,
        smtp_username: str | None = None,
        smtp_password: str | None = None,
        smtp_starttls: bool | None = None,
        smtp_timeout: float | None = None,
        smtp_ssl: bool | None = None,
    ) -> None:
        if engine is None:
            from asm.db.session import get_engine

            self.engine = get_engine()
        else:
            self.engine = engine
        self.session_factory = sessionmaker(bind=self.engine)
        self.runner = runner or DirectScannerRunner()
        self.poll_interval = poll_interval
        self.lease_duration = lease_duration
        self.heartbeat_interval = heartbeat_interval
        self.worker_id = worker_id or (
            f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        )
        self.shutdown_requested = threading.Event()
        self._last_purge_mono: float | None = None

        # SMTP configuration for alert delivery
        if smtp_host is not None:
            self.smtp_host = smtp_host.strip() or None
        else:
            self.smtp_host = os.getenv("SMTP_HOST", "").strip() or None

        self.smtp_port = (
            smtp_port if smtp_port is not None else int(os.getenv("SMTP_PORT", "1025"))
        )
        self.smtp_from = (
            smtp_from if smtp_from is not None else os.getenv("SMTP_FROM", "alerts@asm.local")
        )
        self.smtp_username = (
            smtp_username
            if smtp_username is not None
            else (os.getenv("SMTP_USERNAME", "").strip() or None)
        )
        self.smtp_password = (
            smtp_password
            if smtp_password is not None
            else (os.getenv("SMTP_PASSWORD", "").strip() or None)
        )
        self.smtp_starttls = (
            smtp_starttls
            if smtp_starttls is not None
            else (os.getenv("SMTP_STARTTLS", "false").lower() in ("true", "1", "yes"))
        )
        self.smtp_timeout = (
            smtp_timeout
            if smtp_timeout is not None
            else float(os.getenv("SMTP_TIMEOUT", "10.0"))
        )
        self.smtp_ssl = (
            smtp_ssl
            if smtp_ssl is not None
            else (os.getenv("SMTP_SSL", "false").lower() in ("true", "1", "yes"))
        )

    def install_signal_handlers(self) -> None:
        """Register signal handlers to initiate graceful shutdown on SIGTERM / SIGINT."""

        def _handle_signal(signum: int, frame: Any) -> None:
            logger.info("Signal %d received: initiating graceful worker shutdown", signum)
            self.shutdown_requested.set()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    def run(self) -> None:
        """Main worker execution loop."""
        logger.info(
            "Starting ASM worker %s (poll_interval=%.1fs)",
            self.worker_id,
            self.poll_interval,
        )
        self.install_signal_handlers()

        while not self.shutdown_requested.is_set():
            try:
                self.run_poll_cycle()
            except Exception:
                logger.exception("Unexpected error in worker poll cycle")

            self.shutdown_requested.wait(self.poll_interval)

        logger.info("Worker %s shut down gracefully.", self.worker_id)

    def run_poll_cycle(self) -> bool:
        """Execute one complete polling cycle: recovery, poison pills, scheduling, and claiming."""
        self.reclaim_stale_leases_and_poison_pills()

        # Step: Expire operator overrides that passed verification_expires_at
        try:
            self.expire_operator_overrides()
        except Exception:
            logger.exception("Unexpected error in worker expire_operator_overrides")

        # Step: Re-verify due domains via DNS TXT
        try:
            self.reverify_due_domains()
        except Exception:
            logger.exception("Unexpected error in worker reverify_due_domains")

        # Step: Schedule due scans (before claiming jobs)
        try:
            self.schedule_due_scans()
        except Exception:
            logger.exception(
                "Unexpected error in worker schedule_due_scans; continuing to job claiming"
            )

        # Step: Deliver pending alert notifications (outbox worker step)
        try:
            self.deliver_pending_alerts()
        except Exception:
            logger.exception(
                "Unexpected error in worker deliver_pending_alerts; continuing to job claiming"
            )

        # Step: Retention purge (off unless RETENTION_PURGE_ENABLED, at most hourly)
        try:
            self.purge_retention_if_due()
        except Exception:
            logger.exception("Unexpected error in worker purge_retention_if_due")

        if self.shutdown_requested.is_set():
            return False

        claimed = self.claim_next_job()
        if claimed is None:
            return False

        scan_run_id, domain_id, claim_token, attempts, max_attempts = claimed
        logger.info(
            "Claimed scan_run_id=%d domain_id=%d attempt=%d/%d token=%s",
            scan_run_id,
            domain_id,
            attempts,
            max_attempts,
            claim_token,
        )

        self.execute_scan_run(scan_run_id, domain_id, claim_token, attempts, max_attempts)
        return True

    def purge_retention_if_due(self) -> dict | None:
        """Run the retention purge when enabled and an hour has passed since the last run."""
        if not purge_enabled():
            return None
        now_mono = time.monotonic()
        if self._last_purge_mono is not None and now_mono - self._last_purge_mono < PURGE_EVERY_S:
            return None
        self._last_purge_mono = now_mono
        with self.session_factory() as session:
            return purge_expired(session, dry_run=False)

    def expire_operator_overrides(self, batch_limit: int = 10) -> int:
        """Expire operator-verified domains that have passed verification_expires_at.

        Moves domain back to pending and emits outbox alert if alerts are enabled.
        """
        processed_count = 0
        for _ in range(batch_limit):
            with self.session_factory() as session:
                stmt = (
                    select(Domain)
                    .where(
                        Domain.verification_status == "verified",
                        Domain.verification_method == "operator",
                        Domain.verification_expires_at.is_not(None),
                        Domain.verification_expires_at <= func.now(),
                    )
                    .order_by(Domain.verification_expires_at.asc())
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                domain = session.scalar(stmt)
                if not domain:
                    break

                domain.verification_status = "pending"
                domain.verification_method = "dns_txt"
                domain.verification_expires_at = None
                domain.next_reverification_at = None
                logger.warning(
                    "Operator override expired for domain %s (id=%d); status reset to pending",
                    domain.name,
                    domain.id,
                )

                queue_domain_alert(
                    session,
                    domain,
                    subject="Domain verification lapsed: monitoring paused",
                    body=(
                        f"Operator verification override for '{domain.name}' has "
                        "expired. Automated scheduled monitoring is paused until "
                        "ownership is verified."
                    ),
                )

                record_event(
                    session,
                    org_id=domain.org_id,
                    actor_type="system",
                    action="verification.override_expired",
                    target_type="domain",
                    target_id=str(domain.id),
                    metadata={},
                )

                session.commit()
                processed_count += 1

        return processed_count

    def reverify_due_domains(self, batch_limit: int = 10) -> int:
        """Find verified domains due for DNS re-verification and update posture.

        - match: reset consecutive_misses to 0, reschedule ~24h with jitter
        - definite absence: misses += 1; if misses >= 2: status = lapsed and notify outbox;
          if misses == 1: fast retry in ~1h
        - UNKNOWN (timeout/SERVFAIL): change nothing, retry in ~1h
        """
        processed_count = 0
        for _ in range(batch_limit):
            with self.session_factory() as session:
                stmt = (
                    select(Domain)
                    .where(
                        Domain.verification_status == "verified",
                        Domain.verification_method == "dns_txt",
                        Domain.next_reverification_at <= func.now(),
                    )
                    .order_by(Domain.next_reverification_at.asc())
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                domain = session.scalar(stmt)
                if not domain:
                    break

                now_utc = datetime.now(UTC)
                outcome, detail = check_dns_txt_verification(domain.name, domain.verification_token)
                domain.last_checked_at = now_utc

                just_lapsed = apply_check_outcome(domain, outcome, now_utc)
                if just_lapsed:
                    logger.warning(
                        "Domain %s (id=%d) lapsed after 2 consecutive misses (%s)",
                        domain.name,
                        domain.id,
                        detail,
                    )
                    queue_domain_alert(
                        session,
                        domain,
                        subject="Domain verification lapsed: monitoring paused",
                        body=(
                            f"Domain verification for '{domain.name}' has lapsed "
                            "after 2 consecutive failed DNS checks. Automated "
                            "scheduled monitoring is paused until ownership is "
                            "re-verified."
                        ),
                    )
                    record_event(
                        session,
                        org_id=domain.org_id,
                        actor_type="system",
                        action="verification.lapsed",
                        target_type="domain",
                        target_id=str(domain.id),
                        metadata={
                            "consecutive_misses": domain.consecutive_misses,
                            "outcome": "absent",
                        },
                    )

                session.commit()
                processed_count += 1

        return processed_count

    def schedule_due_scans(self, batch_limit: int = 10) -> int:
        """Find verified domains due for scheduled scanning, queue jobs, and advance schedules.

        Runs up to batch_limit iterations. Each iteration is an isolated short transaction
        locking one due domain with FOR UPDATE SKIP LOCKED.

        Returns:
            Number of due domains processed.
        """
        processed_count = 0

        for _ in range(batch_limit):
            with self.session_factory() as session:
                # 1. Select next due domain
                stmt = (
                    select(Domain)
                    .where(
                        Domain.verification_status == "verified",
                        Domain.scan_interval_hours.is_not(None),
                        Domain.next_scan_at <= func.now(),
                    )
                    .order_by(Domain.next_scan_at.asc())
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                domain = session.scalar(stmt)
                if not domain:
                    break

                # 2. Enqueue scan_run and stages using a nested transaction (savepoint)
                active_scan_exists = False
                try:
                    with session.begin_nested():
                        enqueue_scan(session, domain.id, trigger="scheduled")
                except IntegrityError as err:
                    # Treat ONLY a violation of uq_scan_runs_active_domain as active scan exists
                    err_str = str(err)
                    diag = getattr(getattr(err, "orig", None), "diag", None)
                    constraint_name = getattr(diag, "constraint_name", None)
                    if (
                        constraint_name == "uq_scan_runs_active_domain"
                        or "uq_scan_runs_active_domain" in err_str
                    ):
                        active_scan_exists = True
                        logger.info(
                            "Domain %s (id=%d) already has an active scan; skipping duplicate",
                            domain.name,
                            domain.id,
                        )
                    else:
                        logger.error(
                            "Non-active-scan IntegrityError scheduling domain %s (id=%d): %s",
                            domain.name,
                            domain.id,
                            err,
                        )
                        raise

                # 3. Always advance next_scan_at = now() + interval + random jitter
                jitter_seconds = random.randint(0, 300)  # jitter, not a secret  # nosec B311
                interval_hours = domain.scan_interval_hours
                advance_stmt = (
                    update(Domain)
                    .where(Domain.id == domain.id)
                    .values(
                        next_scan_at=func.now()
                        + text("interval '1 hour' * :h").bindparams(h=interval_hours)
                        + text("interval '1 second' * :s").bindparams(s=jitter_seconds)
                    )
                )
                session.execute(advance_stmt)
                session.commit()

                processed_count += 1
                if not active_scan_exists:
                    logger.info(
                        "Enqueued scheduled scan for domain %s (id=%d)",
                        domain.name,
                        domain.id,
                    )

        return processed_count

    def reclaim_stale_leases_and_poison_pills(self) -> None:
        """Run SQL lease recovery and poison pill termination."""
        with self.session_factory() as session:
            # Poison pill termination: attempts >= max_attempts with expired lease
            poisoned_runs = session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = 'failed',
                        finished_at = now(),
                        claimed_by = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        error = 'Execution aborted: maximum retry attempts ('
                                || max_attempts
                                || ') exceeded without completion (lease expired).'
                    WHERE status = 'running'
                      AND lease_expires_at < now()
                      AND attempts >= max_attempts
                    RETURNING id, error
                    """
                )
            ).fetchall()

            for p_run in poisoned_runs:
                session.execute(
                    text(
                        """
                        UPDATE scan_stages
                        SET status = 'failed',
                            finished_at = now(),
                            error = :error
                        WHERE scan_run_id = :id AND status = 'running'
                        """
                    ),
                    {"id": p_run.id, "error": p_run.error},
                )
                session.execute(
                    text(
                        """
                        UPDATE scan_stages
                        SET status = 'skipped',
                            started_at = coalesce(started_at, now()),
                            finished_at = now(),
                            duration_ms = 0,
                            error = 'Skipped: maximum retry attempts exceeded (lease expired)'
                        WHERE scan_run_id = :id AND status = 'pending'
                        """
                    ),
                    {"id": p_run.id},
                )

            # Stale lease recovery: attempts < max_attempts with expired lease
            # Backoff is computed dynamically per-row in SQL from its own attempts count:
            # base 10s, doubling, capped at 120s, plus random jitter up to 5s.
            session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = 'queued',
                        claimed_by = NULL,
                        claimed_at = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = now() + (
                            LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
                            + (random() * 5.0)
                        ) * INTERVAL '1 second',
                        error = 'Lease expired (worker unresponsive). Re-queued for retry.'
                    WHERE status = 'running'
                      AND lease_expires_at < now()
                      AND attempts < max_attempts
                    """
                )
            )
            session.commit()

    def claim_next_job(self) -> tuple[int, int, uuid.UUID, int, int] | None:
        """Atomically claim the oldest eligible queued scan run."""
        new_token = uuid.uuid4()
        with self.session_factory() as session:
            result = session.execute(
                text(
                    """
                    WITH next_run AS (
                        SELECT id, error
                        FROM scan_runs
                        WHERE status = 'queued'
                          AND (next_attempt_at IS NULL OR next_attempt_at <= now())
                          AND attempts < max_attempts
                        ORDER BY created_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE scan_runs
                    SET status = 'running',
                        started_at = COALESCE(scan_runs.started_at, now()),
                        claimed_by = :worker_id,
                        claim_token = :claim_token,
                        claimed_at = now(),
                        lease_expires_at = now()
                            + CAST(:lease_duration || ' seconds' AS INTERVAL),
                        attempts = attempts + 1,
                        error = NULL
                    FROM next_run
                    WHERE scan_runs.id = next_run.id
                    RETURNING
                        scan_runs.id,
                        scan_runs.domain_id,
                        scan_runs.attempts,
                        scan_runs.max_attempts,
                        next_run.error;
                    """
                ),
                {
                    "worker_id": self.worker_id,
                    "claim_token": new_token,
                    "lease_duration": self.lease_duration,
                },
            )
            row = result.fetchone()
            if not row:
                session.commit()
                return None

            run_id, domain_id, attempts, max_attempts, previous_error = row
            if previous_error:
                logger.info(
                    "Resuming scan_run_id=%d; previous error: %s",
                    run_id,
                    previous_error,
                )

            # Reset any stage stuck in 'running' back to 'pending'
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'pending',
                        started_at = NULL,
                        finished_at = NULL,
                        duration_ms = NULL,
                        error = NULL
                    WHERE scan_run_id = :run_id
                      AND status = 'running'
                    """
                ),
                {"run_id": run_id},
            )
            session.commit()
            return run_id, domain_id, new_token, attempts, max_attempts

    def _verify_fence(self, session: Session, scan_run_id: int, claim_token: uuid.UUID) -> None:
        """Verify worker lease ownership via FOR SHARE lock."""
        res = session.execute(
            text(
                """
                SELECT 1 FROM scan_runs
                WHERE id = :id AND status = 'running' AND claim_token = :token
                FOR SHARE
                """
            ),
            {"id": scan_run_id, "token": claim_token},
        ).fetchone()
        if not res:
            raise LostLeaseError(
                f"Worker {self.worker_id} lost lease for scan_run_id={scan_run_id}"
            )

    def execute_scan_run(
        self,
        scan_run_id: int,
        domain_id: int,
        claim_token: uuid.UUID,
        attempts: int,
        max_attempts: int,
    ) -> None:
        """Execute the 5-stage pipeline with fenced writes, heartbeat, and signal checks."""
        lost_lease_event = threading.Event()
        heartbeat = HeartbeatThread(
            session_factory=self.session_factory,
            scan_run_id=scan_run_id,
            claim_token=claim_token,
            lease_duration=self.lease_duration,
            heartbeat_interval=self.heartbeat_interval,
            lost_lease_event=lost_lease_event,
        )
        heartbeat.start()

        reports: dict[str, dict[str, Any]] = {}
        stage_failed_flag = False
        terminal_security_error: str | None = None

        try:
            # 1. Fetch domain record and load existing succeeded stage reports
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                domain = session.get(Domain, domain_id)
                if not domain:
                    raise SecurityGateError(f"Domain ID {domain_id} does not exist.")
                if domain.verification_status != "verified":
                    raise SecurityGateError(
                        f"Target domain '{domain.name}' verification is not active "
                        f"({domain.verification_status})."
                    )
                domain_name = domain.name

                # Load existing succeeded reports for resume capability
                existing_results = (
                    session.query(ScanResult).filter_by(scan_run_id=scan_run_id).all()
                )
                for r in existing_results:
                    reports[r.stage] = r.report

            # Pipeline execution: discover -> probe -> portscan -> inspect -> score
            stages = ["discover", "probe", "portscan", "inspect", "score"]

            for stage in stages:
                if lost_lease_event.is_set():
                    raise LostLeaseError(f"Lease lost detected during stage {stage}")

                # Check SIGTERM signal between stages
                if self.shutdown_requested.is_set():
                    logger.info(
                        "Graceful shutdown requested between stages; releasing job %d",
                        scan_run_id,
                    )
                    self._graceful_release(scan_run_id, claim_token)
                    return

                # Check if this stage already succeeded in a prior attempt
                if stage in reports:
                    logger.info(
                        "Stage '%s' already succeeded for scan_run_id=%d; skipping",
                        stage,
                        scan_run_id,
                    )
                    continue

                # Stage dependency evaluation
                should_skip = False
                skip_reason = None

                if stage in ("probe", "portscan", "score") and "discover" not in reports:
                    should_skip = True
                    skip_reason = "Discover stage did not succeed"
                elif stage == "inspect" and "probe" not in reports:
                    should_skip = True
                    skip_reason = "Probe stage did not succeed"

                if should_skip:
                    self._mark_stage_skipped(scan_run_id, claim_token, stage, skip_reason)
                    continue

                # Worker-side verification gate check before EVERY stage including discover
                with self.session_factory() as session:
                    fresh_domain = session.get(Domain, domain_id)
                    if not fresh_domain or fresh_domain.verification_status != "verified":
                        raise SecurityGateError(
                            f"Domain verification lapsed/revoked for '{domain_name}'"
                        )

                # Mark stage 'running' in short transaction
                self._mark_stage_running(scan_run_id, claim_token, stage)

                # Execute stage logic outside database transaction
                stage_start_mono = time.monotonic()
                try:
                    report = self._run_stage_runner(stage, domain_name, reports)
                    duration_ms = int((time.monotonic() - stage_start_mono) * 1000)

                    # Save stage result & mark stage succeeded in ONE transaction
                    self._save_stage_success(scan_run_id, claim_token, stage, report, duration_ms)
                    reports[stage] = report
                except EXPECTED_SCANNER_ERRORS as exc:
                    duration_ms = int((time.monotonic() - stage_start_mono) * 1000)
                    err_msg = str(exc)
                    logger.warning(
                        "Expected error in stage '%s' for run %d: %s",
                        stage,
                        scan_run_id,
                        err_msg,
                    )
                    self._mark_stage_failed(scan_run_id, claim_token, stage, err_msg, duration_ms)
                    stage_failed_flag = True

                    if isinstance(exc, SecurityGateError):
                        terminal_security_error = err_msg
                        for rem in stages[stages.index(stage) + 1 :]:
                            self._mark_stage_skipped(
                                scan_run_id,
                                claim_token,
                                rem,
                                "Skipped: authorization revoked",
                            )
                        break

                    if stage == "discover":
                        # Discover failure prevents all subsequent stages
                        for rem in ("probe", "portscan", "inspect", "score"):
                            self._mark_stage_skipped(
                                scan_run_id,
                                claim_token,
                                rem,
                                "Skipped due to discover failure",
                            )
                        break

            # Mark final run status
            if terminal_security_error:
                self._mark_run_final(scan_run_id, claim_token, "failed", terminal_security_error)
            elif stage_failed_flag or len(reports) < len(stages):
                # Any stage failure means run failed (partial success visible in scan_results)
                self._mark_run_final(
                    scan_run_id,
                    claim_token,
                    "failed",
                    "One or more scan stages failed or were skipped",
                )
            else:
                summary, changes, baseline_id = self._perform_change_detection(
                    scan_run_id, domain_id, reports
                )

                # Build alert subject/body and recipient rows in memory BEFORE the final
                # fenced transaction, inside try/except.
                alert_rows: list[dict[str, str]] = []
                if summary.get("status") == "computed":
                    try:
                        with self.session_factory() as session:
                            domain_obj = session.get(Domain, domain_id)
                            if (
                                domain_obj
                                and domain_obj.alerts_enabled
                                and domain_obj.alert_emails
                                and domain_obj.verification_status == "verified"
                            ):
                                should_alert, triggering_changes = should_trigger_alerts(
                                    alerts_enabled=domain_obj.alerts_enabled,
                                    alert_emails=domain_obj.alert_emails,
                                    verified=domain_obj.is_verified,
                                    alert_min_severity=domain_obj.alert_min_severity,
                                    change_summary=summary,
                                    changes=changes,
                                )
                                if should_alert:
                                    subject, body = build_alert_digest(
                                        domain_name=domain_obj.name,
                                        scan_run_id=scan_run_id,
                                        changes=changes,
                                        triggering_changes=triggering_changes,
                                    )
                                    for email in domain_obj.alert_emails:
                                        alert_rows.append({
                                            "recipient": email,
                                            "subject": subject,
                                            "body": body,
                                        })
                    except Exception as alert_exc:
                        logger.exception(
                            "Failed building alerts for scan_run_id=%d: %s",
                            scan_run_id,
                            alert_exc,
                        )
                        summary["alert_error"] = sanitize_error_text(str(alert_exc))
                        alert_rows = []

                self._mark_run_final(
                    scan_run_id,
                    claim_token,
                    "succeeded",
                    None,
                    change_detection=summary,
                    changes=changes,
                    domain_id=domain_id,
                    baseline_scan_run_id=baseline_id,
                    alert_rows=alert_rows,
                )

        except SecurityGateError as exc:
            logger.warning(
                "Terminal SecurityGateError for scan_run_id=%d: %s; failing permanently",
                scan_run_id,
                exc,
            )
            # Only stages that never finished are skipped; succeeded/failed stages
            # keep their real status and results.
            try:
                self._skip_unfinished_stages(
                    scan_run_id, claim_token, "Skipped: authorization revoked"
                )
            except LostLeaseError:
                logger.warning("Lost lease while failing scan_run_id=%d", scan_run_id)
                return
            self._mark_run_final(scan_run_id, claim_token, "failed", str(exc))

        except LostLeaseError as exc:
            logger.warning(
                "Worker lost lease for scan_run_id=%d: %s; discarding in-memory work",
                scan_run_id,
                exc,
            )
            return

        except Exception as exc:
            logger.exception("Unexpected exception executing scan_run_id=%d", scan_run_id)
            if not lost_lease_event.is_set():
                self._handle_unexpected_worker_exception(
                    scan_run_id, claim_token, str(exc), attempts, max_attempts
                )

        finally:
            heartbeat.stop()

    def _run_stage_runner(
        self, stage: str, domain: str, reports: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Dispatch stage execution to the configured IScannerRunner."""
        if stage == "discover":
            return self.runner.run_discover(domain)
        elif stage == "probe":
            return self.runner.run_probe(domain, reports["discover"], authorized=True)
        elif stage == "portscan":
            return self.runner.run_portscan(domain, reports["discover"], authorized=True)
        elif stage == "inspect":
            return self.runner.run_inspect(domain, reports["probe"], authorized=True)
        elif stage == "score":
            return self.runner.run_score(
                domain,
                discover_report=reports["discover"],
                probe_report=reports.get("probe"),
                portscan_report=reports.get("portscan"),
                inspect_report=reports.get("inspect"),
            )
        else:
            raise ValueError(f"Unknown scan stage: {stage}")

    def _mark_stage_running(self, scan_run_id: int, claim_token: uuid.UUID, stage: str) -> None:
        """Mark stage status as 'running' in a short transaction with fence check."""
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'running',
                        started_at = now()
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage},
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to set stage {stage} to running: 0 rows affected")
            session.commit()

    def _save_stage_success(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        stage: str,
        report: dict[str, Any],
        duration_ms: int,
    ) -> None:
        """Store artifact report in scan_results and mark stage succeeded in ONE transaction."""
        import json

        report_json = json.dumps(report)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)

            # Insert report into scan_results
            res_results = session.execute(
                text(
                    """
                    INSERT INTO scan_results (scan_run_id, stage, report, created_at)
                    SELECT :id, :stage, CAST(:report_json AS jsonb), now()
                    WHERE EXISTS (
                        SELECT 1 FROM scan_runs
                        WHERE id = :id AND status = 'running' AND claim_token = :token
                    )
                    """
                ),
                {
                    "id": scan_run_id,
                    "stage": stage,
                    "report_json": report_json,
                    "token": claim_token,
                },
            )
            if res_results.rowcount == 0:
                raise LostLeaseError(
                    f"Failed to insert scan_result for stage {stage}: 0 rows affected"
                )

            # Update stage status to succeeded
            res_stages = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'succeeded',
                        finished_at = now(),
                        duration_ms = :duration_ms,
                        error = NULL
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage, "duration_ms": duration_ms},
            )
            if res_stages.rowcount == 0:
                raise LostLeaseError(
                    f"Failed to update scan_stage {stage} to succeeded: 0 rows affected"
                )

            session.commit()

    def _mark_stage_failed(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        stage: str,
        error_msg: str,
        duration_ms: int,
    ) -> None:
        """Mark stage as 'failed' in a short transaction."""
        sanitized_error = sanitize_error_text(error_msg)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'failed',
                        finished_at = now(),
                        duration_ms = :duration_ms,
                        error = :error
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {
                    "id": scan_run_id,
                    "stage": stage,
                    "duration_ms": duration_ms,
                    "error": sanitized_error,
                },
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to mark stage {stage} failed: 0 rows affected")
            session.commit()

    def _mark_stage_skipped(
        self, scan_run_id: int, claim_token: uuid.UUID, stage: str, reason: str | None
    ) -> None:
        """Mark stage as 'skipped' in a short transaction."""
        sanitized_reason = sanitize_error_text(reason)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'skipped',
                        started_at = now(),
                        finished_at = now(),
                        duration_ms = 0,
                        error = :reason
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage, "reason": sanitized_reason},
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to mark stage {stage} skipped: 0 rows affected")
            session.commit()

    def _skip_unfinished_stages(
        self, scan_run_id: int, claim_token: uuid.UUID, reason: str
    ) -> None:
        """Mark every stage that is still 'pending' or 'running' as 'skipped'.

        Stages that already succeeded or failed are left untouched, so their
        status and stored results stay truthful.
        """
        sanitized_reason = sanitize_error_text(reason)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'skipped',
                        started_at = coalesce(started_at, now()),
                        finished_at = now(),
                        duration_ms = 0,
                        error = :reason
                    WHERE scan_run_id = :id AND status IN ('pending', 'running')
                    """
                ),
                {"id": scan_run_id, "reason": sanitized_reason},
            )
            session.commit()

    def _perform_change_detection(
        self,
        scan_run_id: int,
        domain_id: int,
        new_reports: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int | None]:
        """Perform in-memory change detection against the most recent earlier succeeded scan."""
        from asm.changes import detect_changes, evaluate_removal_eligibility

        with self.session_factory() as session:
            baseline_row = session.execute(
                text(
                    """
                    SELECT id FROM scan_runs
                    WHERE domain_id = :domain_id AND status = 'succeeded' AND id < :current_id
                    ORDER BY id DESC LIMIT 1
                    """
                ),
                {"domain_id": domain_id, "current_id": scan_run_id},
            ).fetchone()

            if not baseline_row:
                summary = {
                    "status": "baseline",
                    "baseline_scan_run_id": None,
                    "removal_detection": "skipped",
                    "skip_reason": "No previous succeeded scan (first scan is baseline)",
                    "error": None,
                    "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                }
                return summary, [], None

            baseline_id = baseline_row[0]
            results = session.execute(
                text(
                    """
                    SELECT stage, report FROM scan_results
                    WHERE scan_run_id = :baseline_id
                    """
                ),
                {"baseline_id": baseline_id},
            ).fetchall()
            baseline_reports = {r[0]: r[1] for r in results}

        base_disc = baseline_reports.get("discover") or {}
        new_disc = new_reports.get("discover") or {}
        allow_removal, skip_reason = evaluate_removal_eligibility(base_disc, new_disc)

        try:
            changes = detect_changes(baseline_reports, new_reports, allow_removal=allow_removal)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for ch in changes:
                sev = ch.get("severity", "INFO").lower()
                if sev in counts:
                    counts[sev] += 1

            summary = {
                "status": "computed",
                "baseline_scan_run_id": baseline_id,
                "removal_detection": "performed" if allow_removal else "skipped",
                "skip_reason": skip_reason,
                "error": None,
                "counts": counts,
            }
            return summary, changes, baseline_id

        except Exception as exc:
            logger.exception(
                "Change detection failed for scan_run_id=%d against baseline_id=%d",
                scan_run_id,
                baseline_id,
            )
            summary = {
                "status": "failed",
                "baseline_scan_run_id": baseline_id,
                "removal_detection": "skipped",
                "skip_reason": None,
                "error": sanitize_error_text(str(exc)),
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
            return summary, [], baseline_id

    def _mark_run_final(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        status: str,
        error_msg: str | None,
        change_detection: dict[str, Any] | None = None,
        changes: list[dict[str, Any]] | None = None,
        domain_id: int | None = None,
        baseline_scan_run_id: int | None = None,
        alert_rows: list[dict[str, str]] | None = None,
    ) -> None:
        """Set terminal status for scan_run and clear claim tokens."""
        sanitized_error = sanitize_error_text(error_msg)
        change_detection_json = (
            json.dumps(change_detection) if change_detection is not None else None
        )
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)

            # Insert detected changes in the fenced transaction
            if changes and baseline_scan_run_id and domain_id:
                for ch in changes:
                    session.execute(
                        text(
                            """
                            INSERT INTO scan_changes (
                                domain_id,
                                scan_run_id,
                                baseline_scan_run_id,
                                change_type,
                                category,
                                severity,
                                asset,
                                detail,
                                evidence,
                                previous_state,
                                new_state,
                                observed_at,
                                created_at
                            ) VALUES (
                                :domain_id,
                                :scan_run_id,
                                :baseline_scan_run_id,
                                :change_type,
                                :category,
                                :severity,
                                :asset,
                                :detail,
                                :evidence,
                                CAST(:previous_state AS jsonb),
                                CAST(:new_state AS jsonb),
                                :observed_at,
                                now()
                            )
                            """
                        ),
                        {
                            "domain_id": domain_id,
                            "scan_run_id": scan_run_id,
                            "baseline_scan_run_id": baseline_scan_run_id,
                            "change_type": ch["change_type"],
                            "category": ch["category"],
                            "severity": ch["severity"],
                            "asset": ch["asset"],
                            "detail": ch["detail"],
                            "evidence": ch["evidence"],
                            "previous_state": (
                                json.dumps(ch["previous_state"])
                                if ch.get("previous_state") is not None
                                else None
                            ),
                            "new_state": (
                                json.dumps(ch["new_state"])
                                if ch.get("new_state") is not None
                                else None
                            ),
                            "observed_at": ch["observed_at"],
                        },
                    )

            # Insert alert notifications into outbox in the same fenced transaction
            if alert_rows and domain_id:
                for alert in alert_rows:
                    session.execute(
                        text(
                            """
                            INSERT INTO alert_notifications (
                                domain_id,
                                scan_run_id,
                                recipient,
                                subject,
                                body,
                                status,
                                attempts,
                                max_attempts,
                                next_attempt_at,
                                created_at
                            ) VALUES (
                                :domain_id,
                                :scan_run_id,
                                :recipient,
                                :subject,
                                :body,
                                'pending',
                                0,
                                5,
                                now(),
                                now()
                            )
                            ON CONFLICT (scan_run_id, recipient) DO NOTHING
                            """
                        ),
                        {
                            "domain_id": domain_id,
                            "scan_run_id": scan_run_id,
                            "recipient": alert["recipient"],
                            "subject": alert["subject"],
                            "body": alert["body"],
                        },
                    )

            res = session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = :status,
                        finished_at = now(),
                        claimed_by = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        error = :error,
                        change_detection = CAST(:change_detection AS jsonb)
                    WHERE id = :id AND status = 'running' AND claim_token = :token
                    """
                ),
                {
                    "id": scan_run_id,
                    "status": status,
                    "error": sanitized_error,
                    "token": claim_token,
                    "change_detection": change_detection_json,
                },
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to set final status for scan_run_id={scan_run_id}")

            # Terminal-state invariant:
            # any stage still 'running' -> 'failed' with the run's error
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'failed',
                        finished_at = now(),
                        error = :error
                    WHERE scan_run_id = :id AND status = 'running'
                    """
                ),
                {"id": scan_run_id, "error": sanitized_error or "Scan run terminated"},
            )
            # any 'pending' stage -> 'skipped' with a reason
            skip_reason = sanitized_error or (
                "Scan run succeeded" if status == "succeeded" else "Skipped: scan run terminated"
            )
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'skipped',
                        started_at = coalesce(started_at, now()),
                        finished_at = now(),
                        duration_ms = 0,
                        error = :reason
                    WHERE scan_run_id = :id AND status = 'pending'
                    """
                ),
                {"id": scan_run_id, "reason": skip_reason},
            )
            session.commit()

    def _handle_unexpected_worker_exception(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        error_msg: str,
        attempts: int,
        max_attempts: int,
    ) -> None:
        """Requeue or fail run on unexpected error using DB clock and retry budget."""
        try:
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                if attempts < max_attempts:
                    sanitized_error = sanitize_error_text(
                        f"Unexpected worker error: {error_msg}"
                    )
                    # Requeue with SQL exponential backoff + jitter
                    session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET status = 'queued',
                                claimed_by = NULL,
                                claim_token = NULL,
                                lease_expires_at = NULL,
                                next_attempt_at = now() + (
                                    LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
                                    + (random() * 5.0)
                                ) * INTERVAL '1 second',
                                error = :error
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": scan_run_id,
                            "token": claim_token,
                            "error": sanitized_error,
                        },
                    )
                else:
                    # Attempts reached max_attempts; mark failed permanently
                    sanitized_error = sanitize_error_text(
                        f"Max retry attempts exceeded: {error_msg}"
                    )
                    res = session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET status = 'failed',
                                finished_at = now(),
                                claimed_by = NULL,
                                claim_token = NULL,
                                lease_expires_at = NULL,
                                error = :error
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": scan_run_id,
                            "token": claim_token,
                            "error": sanitized_error,
                        },
                    )
                    if res.rowcount > 0:
                        # Terminal-state invariant:
                        # any stage still 'running' -> 'failed' with the run's error
                        session.execute(
                            text(
                                """
                                UPDATE scan_stages
                                SET status = 'failed',
                                    finished_at = now(),
                                    error = :error
                                WHERE scan_run_id = :id AND status = 'running'
                                """
                            ),
                            {"id": scan_run_id, "error": sanitized_error},
                        )
                        # any 'pending' stage -> 'skipped' with a reason
                        session.execute(
                            text(
                                """
                                UPDATE scan_stages
                                SET status = 'skipped',
                                    started_at = coalesce(started_at, now()),
                                    finished_at = now(),
                                    duration_ms = 0,
                                    error = 'Skipped: maximum retry attempts exceeded'
                                WHERE scan_run_id = :id AND status = 'pending'
                                """
                            ),
                            {"id": scan_run_id},
                        )
                session.commit()
        except Exception as exc:
            logger.error("Failed to update status on unexpected exception: %s", exc)

    def _graceful_release(self, scan_run_id: int, claim_token: uuid.UUID) -> None:
        """Release claimed run gracefully on SIGTERM without consuming an attempt."""
        try:
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                session.execute(
                    text(
                        """
                        UPDATE scan_runs
                        SET status = 'queued',
                            claimed_by = NULL,
                            claimed_at = NULL,
                            claim_token = NULL,
                            lease_expires_at = NULL,
                            attempts = GREATEST(attempts - 1, 0)
                        WHERE id = :id AND status = 'running' AND claim_token = :token
                        """
                    ),
                    {"id": scan_run_id, "token": claim_token},
                )
                session.commit()
                logger.info("Successfully released scan_run_id=%d gracefully", scan_run_id)
        except Exception as exc:
            logger.error("Failed graceful release for scan_run_id=%d: %s", scan_run_id, exc)

    def _defer_if_daily_alert_quota_reached(
        self, session: Session, notification_id: int, domain_id: int
    ) -> bool:
        """Postpone a notification if its domain already sent the daily maximum.

        The email is not dropped and no attempt is counted: next_attempt_at
        moves to when the oldest send in the 24-hour window expires.
        Returns True if the notification was deferred.
        """
        oldest_in_window = session.execute(
            text(
                """
                SELECT count(*) AS sent, min(sent_at) AS oldest
                FROM alert_notifications
                WHERE domain_id = :domain_id AND status = 'sent'
                  AND sent_at > now() - interval '24 hours'
                """
            ),
            {"domain_id": domain_id},
        ).mappings().one()
        if oldest_in_window["sent"] < MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY:
            return False
        session.execute(
            text(
                """
                UPDATE alert_notifications
                SET next_attempt_at = :oldest + interval '24 hours'
                WHERE id = :id
                """
            ),
            {"id": notification_id, "oldest": oldest_in_window["oldest"]},
        )
        logger.warning(
            "Daily alert email quota reached for domain_id=%d (%d per 24h); "
            "notification id=%d deferred",
            domain_id,
            MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY,
            notification_id,
        )
        return True

    def deliver_pending_alerts(self, batch_limit: int = 10) -> int:
        """Deliver pending alert notifications using transactional outbox pattern.

        Each notification is processed in its own transaction.
        The delivery transaction holds the row lock (FOR UPDATE SKIP LOCKED)
        during the SMTP send (bounded by a socket timeout, default 10s).
        Holding the row lock during send prevents double sends by concurrent
        workers. If a crash occurs after SMTP accepts the email but before commit,
        the transaction rolls back and the email may be re-sent (at-least-once).

        Returns:
            Number of alert notifications successfully delivered.
        """
        if not self.smtp_host:
            return 0

        delivered_count = 0
        for _ in range(batch_limit):
            with self.session_factory() as session:
                # 1. Claim single pending notification with FOR UPDATE SKIP LOCKED
                stmt = text(
                    """
                    SELECT id, domain_id, scan_run_id, recipient, subject,
                           body, attempts, max_attempts
                    FROM alert_notifications
                    WHERE status = 'pending' AND next_attempt_at <= now()
                    ORDER BY next_attempt_at ASC, id ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                    """
                )
                row = session.execute(stmt).mappings().fetchone()
                if not row:
                    break

                if self._defer_if_daily_alert_quota_reached(session, row["id"], row["domain_id"]):
                    session.commit()
                    continue

                delivery_error = None
                try:
                    # Hold row lock while sending via smtplib
                    send_smtp_email(
                        host=self.smtp_host,
                        port=self.smtp_port,
                        from_addr=self.smtp_from,
                        to_addr=row["recipient"],
                        subject=row["subject"],
                        body=row["body"],
                        username=self.smtp_username,
                        password=self.smtp_password,
                        use_starttls=self.smtp_starttls,
                        timeout=self.smtp_timeout,
                        use_ssl=self.smtp_ssl,
                    )
                except Exception as exc:
                    delivery_error = sanitize_error_text(str(exc))
                    logger.warning(
                        "Alert delivery failed id=%d attempt=%d/%d: %s",
                        row["id"],
                        row["attempts"] + 1,
                        row["max_attempts"],
                        delivery_error,
                    )

                if delivery_error is None:
                    session.execute(
                        text(
                            """
                            UPDATE alert_notifications
                            SET status = 'sent',
                                sent_at = now(),
                                attempts = attempts + 1,
                                last_error = NULL
                            WHERE id = :id
                            """
                        ),
                        {"id": row["id"]},
                    )
                    delivered_count += 1
                else:
                    new_attempts = row["attempts"] + 1
                    if new_attempts >= row["max_attempts"]:
                        session.execute(
                            text(
                                """
                                UPDATE alert_notifications
                                SET status = 'failed',
                                    attempts = :attempts,
                                    last_error = :err
                                WHERE id = :id
                                """
                            ),
                            {"id": row["id"], "attempts": new_attempts, "err": delivery_error},
                        )
                    else:
                        # Exponential backoff: 30s * 2^(attempts-1) + jitter (0-5s).
                        # Bandit B311 accepted: retry jitter, not a secret or token.
                        jitter = random.uniform(0, 5)  # retry jitter, not a secret  # nosec B311
                        backoff_seconds = int(30 * (2 ** (new_attempts - 1)) + jitter)
                        session.execute(
                            text(
                                """
                                UPDATE alert_notifications
                                SET attempts = :attempts,
                                    next_attempt_at = now() + make_interval(secs => :s),
                                    last_error = :err
                                WHERE id = :id
                                """
                            ),
                            {
                                "id": row["id"],
                                "attempts": new_attempts,
                                "err": delivery_error,
                                "s": backoff_seconds,
                            },
                        )

                session.commit()

        return delivered_count
