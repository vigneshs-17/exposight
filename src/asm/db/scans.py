"""Database operations and helper functions for scan runs."""

from __future__ import annotations

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from asm.db.models import Domain, ScanRun, ScanStage


class UnverifiedDomainError(ValueError):
    """Raised when attempting to enqueue a scan for a domain that is not verified."""

    pass


def enqueue_scan(
    session: Session,
    domain_id: int,
    trigger: str,
    idempotency_key: str | None = None,
) -> ScanRun:
    """Insert a queued scan_run and its 5 pending stage tracking rows.

    Enforces that only domains with status 'verified' can have scans enqueued.

    Args:
        session: Active SQLAlchemy database session.
        domain_id: Target domain foreign key ID.
        trigger: Scan initiation mechanism ("manual" or "scheduled").
        idempotency_key: Optional client idempotency key for deduplication.

    Returns:
        The newly created ScanRun instance.

    Raises:
        UnverifiedDomainError: If the domain does not exist or is not verified.
        IntegrityError: If a database constraint (such as active scan or idempotency key)
            is violated.
    """
    domain = session.get(Domain, domain_id)
    if domain is None or not domain.is_verified:
        raise UnverifiedDomainError(
            f"Domain ID {domain_id} is not verified. "
            "Ownership verification is required before scanning."
        )

    scan_run = ScanRun(
        domain_id=domain_id,
        status="queued",
        trigger=trigger,
        idempotency_key=idempotency_key,
        attempts=0,
        max_attempts=3,
    )
    session.add(scan_run)
    session.flush()

    for stage_name in ("discover", "probe", "portscan", "inspect", "score"):
        stage = ScanStage(
            scan_run_id=scan_run.id,
            stage=stage_name,
            status="pending",
        )
        session.add(stage)
    session.flush()

    return scan_run


def cancel_queued_scans_for_domain(
    session: Session,
    domain_id: int,
    reason: str = "Domain verification is not active.",
) -> int:
    """Cancel any queued scan runs for a domain and skip their pending stages.

    Ensures that unverified or lapsed domains do not strand queued scans that
    block future scans via the uq_scan_runs_active_domain partial unique index.
    """
    queued_ids = session.scalars(
        select(ScanRun.id)
        .where(ScanRun.domain_id == domain_id, ScanRun.status == "queued")
        .with_for_update(of=ScanRun)
    ).all()
    if queued_ids:
        session.execute(
            update(ScanRun)
            .where(ScanRun.id.in_(queued_ids))
            .values(
                status="cancelled",
                finished_at=func.now(),
                error=reason,
            )
        )
        session.execute(
            update(ScanStage)
            .where(ScanStage.scan_run_id.in_(queued_ids), ScanStage.status == "pending")
            .values(
                status="skipped",
                finished_at=func.now(),
                duration_ms=0,
                error=f"Skipped: {reason}",
            )
        )
    return len(queued_ids)

