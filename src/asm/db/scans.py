"""Database operations and helper functions for scan runs."""

from __future__ import annotations

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
