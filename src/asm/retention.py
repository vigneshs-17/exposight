"""Retention purge (v3.6c B-5, D8/D9).

Deletes old scans, finished alert notifications and closed invites. Off by default:
the worker runs it only when RETENTION_PURGE_ENABLED is true, and the operator can
preview it with `asm-admin purge --dry-run`. audit_events are never touched (the app
role cannot delete them anyway).
"""

import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, delete, func, or_, select
from sqlalchemy.orm import Session

from asm.db.models import AlertNotification, OrgInvite, ScanChange, ScanRun

logger = logging.getLogger(__name__)

SCAN_RETENTION = timedelta(days=180)
NOTIFICATION_RETENTION = timedelta(days=90)
INVITE_RETENTION = timedelta(days=30)


def purge_enabled() -> bool:
    """Return True only when RETENTION_PURGE_ENABLED is explicitly turned on."""
    return os.getenv("RETENTION_PURGE_ENABLED", "false").strip().lower() in ("true", "1", "yes")


def _purgeable_scans(now: datetime) -> Select:
    """Finished scans older than SCAN_RETENTION, except each domain's latest succeeded
    scan (the next change-detection baseline) and any scan still used as the baseline
    of a stored change (deleting it would cascade to that newer scan's changes).
    """
    latest_succeeded = (
        select(func.max(ScanRun.id))
        .where(ScanRun.status == "succeeded")
        .group_by(ScanRun.domain_id)
    )
    return select(ScanRun.id).where(
        ScanRun.status.in_(("succeeded", "failed")),
        ScanRun.created_at < now - SCAN_RETENTION,
        ScanRun.id.not_in(latest_succeeded),
        ~select(ScanChange.id).where(ScanChange.baseline_scan_run_id == ScanRun.id).exists(),
    )


def _purgeable_notifications(now: datetime) -> Select:
    return select(AlertNotification.id).where(
        AlertNotification.status.in_(("sent", "failed")),
        AlertNotification.created_at < now - NOTIFICATION_RETENTION,
    )


def _purgeable_invites(now: datetime) -> Select:
    cutoff = now - INVITE_RETENTION
    return select(OrgInvite.id).where(
        or_(
            OrgInvite.accepted_at < cutoff,
            OrgInvite.revoked_at < cutoff,
            OrgInvite.expires_at < cutoff,
        )
    )


def purge_expired(session: Session, *, dry_run: bool, now: datetime | None = None) -> dict:
    """Count (dry_run) or delete everything past its retention period. Commits when not
    a dry run. Returns {"scans": n, "alert_notifications": n, "invites": n}.

    A scan that stops being a baseline (because the newer scan using it was purged)
    becomes purgeable on the next run.
    """
    now = now or datetime.now(UTC)
    targets = {
        "scans": (ScanRun, _purgeable_scans(now)),
        "alert_notifications": (AlertNotification, _purgeable_notifications(now)),
        "invites": (OrgInvite, _purgeable_invites(now)),
    }
    counts: dict[str, int] = {}
    for name, (model, ids) in targets.items():
        if dry_run:
            counts[name] = session.scalar(select(func.count()).select_from(ids.subquery())) or 0
        else:
            stmt = (
                delete(model).where(model.id.in_(ids)).execution_options(synchronize_session=False)
            )
            counts[name] = session.execute(stmt).rowcount or 0
    if not dry_run:
        session.commit()
    logger.info("Retention purge (dry_run=%s): %s", dry_run, counts)
    return counts
