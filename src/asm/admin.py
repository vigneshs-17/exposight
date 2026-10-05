"""Administrative CLI operations for ASM SaaS."""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from asm.audit import record_event
from asm.db.models import Domain, Membership, Organization, ScanRun, ScanStage, User
from asm.db.session import get_session_factory
from asm.logredact import install_log_redaction
from asm.verification import generate_verification_token, queue_domain_alert

logger = logging.getLogger(__name__)


def move_domain(
    session: Session,
    domain_id: int,
    target_org_id: int,
) -> int:
    """Move a domain from the legacy quarantine organization into a target organization.

    Security & Safety Invariants:
    1. A domain can ONLY be moved if its current org has system_kind == 'legacy_quarantine'.
       Moving between ordinary customer orgs via this command is strictly forbidden (exit 1).
    2. The target organization must exist (exit 1).
    3. The target organization cannot already contain a domain with the same name (exit 1).
    4. The domain cannot have a queued or running scan (exit 1).
    5. Ownership proof, alert recipients and schedule belong to the old org, so the
       move resets them: verification back to pending with a new token, alerts
       disabled with no recipients, schedule off. The new org must re-verify.
    """
    domain = session.get(Domain, domain_id)
    if not domain:
        sys.stderr.write(f"Error: Domain with ID {domain_id} does not exist.\n")
        return 1

    current_org = session.get(Organization, domain.org_id)
    if not current_org or current_org.system_kind != "legacy_quarantine":
        sys.stderr.write(
            f"Error: Domain {domain_id} ('{domain.name}') cannot be moved. "
            f"Current organization {domain.org_id} is not a legacy quarantine organization.\n"
        )
        return 1

    target_org = session.get(Organization, target_org_id)
    if not target_org:
        sys.stderr.write(f"Error: Target organization with ID {target_org_id} does not exist.\n")
        return 1

    conflict = session.scalar(
        select(Domain.id).where(
            Domain.org_id == target_org_id,
            Domain.name == domain.name,
            Domain.id != domain_id,
        )
    )
    if conflict:
        sys.stderr.write(
            f"Error: Target organization {target_org_id} already contains domain "
            f"'{domain.name}' (domain_id={conflict}).\n"
        )
        return 1

    # Lock the domain row so the worker cannot start a scan between check and move.
    session.execute(select(Domain.id).where(Domain.id == domain_id).with_for_update())
    active_scan_id = session.scalar(
        select(ScanRun.id).where(
            ScanRun.domain_id == domain_id,
            ScanRun.status.in_(("queued", "running")),
        )
    )
    if active_scan_id:
        sys.stderr.write(
            f"Error: Domain {domain_id} ('{domain.name}') has an active scan "
            f"(scan_run_id={active_scan_id}). Wait for it to finish, then retry.\n"
        )
        return 1

    old_org_id = domain.org_id
    domain.org_id = target_org_id

    # Reset state that the previous org established or configured.
    domain.verification_status = "pending"
    domain.verification_method = "dns_txt"
    domain.verification_token = generate_verification_token()
    domain.verified_at = None
    domain.verification_reason = None
    domain.verification_expires_at = None
    domain.next_reverification_at = None
    domain.consecutive_misses = 0
    domain.alerts_enabled = False
    domain.alert_emails = []
    domain.scan_interval_hours = None
    domain.next_scan_at = None
    reset_flags = {"verification_reset": True, "alerts_reset": True, "schedule_reset": True}

    # Record dual events in the same transaction
    record_event(
        session,
        org_id=old_org_id,
        actor_type="operator",
        action="domain.moved",
        target_type="domain",
        target_id=str(domain_id),
        metadata={
            "to_org_id": target_org_id,
            "reason": f"Moved to org {target_org_id}",
            **reset_flags,
        },
    )
    record_event(
        session,
        org_id=target_org_id,
        actor_type="operator",
        action="domain.moved",
        target_type="domain",
        target_id=str(domain_id),
        metadata={
            "from_org_id": old_org_id,
            "reason": f"Moved from org {old_org_id}",
            **reset_flags,
        },
    )

    session.commit()
    print(
        f"Successfully moved domain {domain_id} ('{domain.name}') from legacy quarantine "
        f"(org {old_org_id}) to organization {target_org_id} ('{target_org.name}')."
    )
    return 0


def verify_domain(
    session: Session,
    domain_id: int,
    reason: str,
    expires_in_days: int = 30,
) -> int:
    """Grant an operator override verification to a domain.

    Invariants:
    - Reason is required and cannot be empty or whitespace-only (exit 1).
    - Expires in days must be between 1 and 90 (default: 30) (exit 1).
    - Marks domain verified with method 'operator'.
    - Re-verification in worker skips operator-verified domains until expired/revoked.
    """
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        sys.stderr.write("Error: --reason is required and cannot be empty.\n")
        return 1

    if expires_in_days < 1 or expires_in_days > 90:
        sys.stderr.write("Error: --expires-in-days must be between 1 and 90.\n")
        return 1

    domain = session.get(Domain, domain_id)
    if not domain:
        sys.stderr.write(f"Error: Domain with ID {domain_id} does not exist.\n")
        return 1

    now_utc = datetime.now(UTC)
    domain.verification_status = "verified"
    domain.verification_method = "operator"
    domain.verification_reason = cleaned_reason
    domain.verification_expires_at = now_utc + timedelta(days=expires_in_days)
    domain.verified_at = now_utc
    domain.consecutive_misses = 0
    domain.next_reverification_at = None

    record_event(
        session,
        org_id=domain.org_id,
        actor_type="operator",
        action="verification.operator_granted",
        target_type="domain",
        target_id=str(domain.id),
        metadata={
            "reason": cleaned_reason,
            "expires_in_days": expires_in_days,
            "verification_expires_at": domain.verification_expires_at.isoformat()
            if domain.verification_expires_at
            else None,
        },
    )

    session.commit()
    logger.info(
        "Operator verified domain %s (id=%d). Reason: %s. Expires: %s",
        domain.name,
        domain.id,
        cleaned_reason,
        domain.verification_expires_at.isoformat(),
    )
    print(
        f"Successfully operator-verified domain {domain_id} ('{domain.name}'). "
        f"Method: operator. Reason: {cleaned_reason}. "
        f"Expires: {domain.verification_expires_at.isoformat()}."
    )
    return 0


def revoke_verification(
    session: Session,
    domain_id: int,
    reason: str,
) -> int:
    """Revoke verification of a domain, resetting its status to pending.

    Invariants:
    - Reason is required and cannot be empty or whitespace-only (exit 1).
    - Status is reset to 'pending', method to 'dns_txt'.
    - If alerts are enabled, queues an alert notification in the outbox.
    """
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        sys.stderr.write("Error: --reason is required and cannot be empty.\n")
        return 1

    domain = session.get(Domain, domain_id)
    if not domain:
        sys.stderr.write(f"Error: Domain with ID {domain_id} does not exist.\n")
        return 1

    domain.verification_status = "pending"
    domain.verification_method = "dns_txt"
    domain.verification_reason = f"Revoked by operator: {cleaned_reason}"
    domain.verification_expires_at = None
    domain.verified_at = None
    domain.consecutive_misses = 0
    domain.next_reverification_at = None

    queue_domain_alert(
        session,
        domain,
        subject="Domain verification lapsed: monitoring paused",
        body=(
            f"Domain verification for '{domain.name}' has been revoked by an operator. "
            f"Reason: {cleaned_reason}. Automated scheduled monitoring is paused "
            "until ownership is verified."
        ),
    )

    record_event(
        session,
        org_id=domain.org_id,
        actor_type="operator",
        action="verification.operator_revoked",
        target_type="domain",
        target_id=str(domain.id),
        metadata={"reason": cleaned_reason},
    )

    session.commit()
    logger.info(
        "Operator revoked verification for domain %s (id=%d). Reason: %s",
        domain.name,
        domain.id,
        cleaned_reason,
    )
    print(
        f"Successfully revoked verification for domain {domain_id} ('{domain.name}'). "
        "Status reset to pending."
    )
    return 0


def _parse_user_id(raw: str) -> uuid.UUID | None:
    """Parse a user UUID argument; print an error and return None if invalid."""
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError):
        sys.stderr.write(f"Error: '{raw}' is not a valid user ID (UUID).\n")
        return None


def suspend_user(session: Session, user_id: str, reason: str) -> int:
    """Suspend an account (operator only).

    Effects, in one transaction:
    - users.suspended_at / suspended_reason are set; the next API or dashboard
      request from this user gets 403 "Account suspended".
    - In every organization where ALL owners are now suspended (D4), scan schedules
      are turned off and queued scans are cancelled. Organizations with another
      active owner keep running. Running scans finish normally.
    - One account.suspended audit event per organization the user belongs to (D5),
      with counts only. The reason is operator-only: it is stored on the user row and
      written to the operator log, never to the tenant-visible audit log.
    """
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        sys.stderr.write("Error: --reason is required and cannot be empty.\n")
        return 1
    parsed_id = _parse_user_id(user_id)
    if parsed_id is None:
        return 1

    user = session.scalar(select(User).where(User.id == parsed_id).with_for_update())
    if user is None:
        sys.stderr.write(f"Error: User {parsed_id} does not exist.\n")
        return 1
    if user.suspended_at is not None:
        sys.stderr.write(f"Error: User {parsed_id} is already suspended.\n")
        return 1

    user.suspended_at = datetime.now(UTC)
    user.suspended_reason = cleaned_reason
    session.flush()

    org_ids = session.scalars(
        select(Membership.org_id).where(Membership.user_id == parsed_id).order_by(Membership.org_id)
    ).all()
    total_schedules = total_scans = 0
    for org_id in org_ids:
        schedules = queued = 0
        if _all_owners_suspended(session, org_id):
            schedules, queued = _stop_org_scanning(session, org_id)
        total_schedules += schedules
        total_scans += queued
        record_event(
            session,
            org_id=org_id,
            actor_type="operator",
            action="account.suspended",
            target_type="user",
            target_id=str(parsed_id),
            metadata={
                "user_id": str(parsed_id),
                "schedules_cancelled": schedules,
                "queued_scans_cancelled": queued,
            },
        )

    session.commit()
    logger.warning(
        "Operator suspended user_id=%s orgs=%d schedules_cancelled=%d "
        "queued_scans_cancelled=%d reason=%r",
        parsed_id,
        len(org_ids),
        total_schedules,
        total_scans,
        cleaned_reason,
    )
    print(
        f"Suspended user {parsed_id}: {len(org_ids)} organization(s); "
        f"{total_schedules} schedule(s) turned off and {total_scans} queued scan(s) cancelled "
        "in organizations with no active owner left."
    )
    return 0


def unsuspend_user(session: Session, user_id: str, reason: str) -> int:
    """Lift a suspension. API access returns on the next request.

    Schedules that were turned off by the suspension stay off: an owner must re-enable
    them. Cancelled scans are not re-queued.
    """
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        sys.stderr.write("Error: --reason is required and cannot be empty.\n")
        return 1
    parsed_id = _parse_user_id(user_id)
    if parsed_id is None:
        return 1

    user = session.scalar(select(User).where(User.id == parsed_id).with_for_update())
    if user is None:
        sys.stderr.write(f"Error: User {parsed_id} does not exist.\n")
        return 1
    if user.suspended_at is None:
        sys.stderr.write(f"Error: User {parsed_id} is not suspended.\n")
        return 1

    user.suspended_at = None
    user.suspended_reason = None
    org_ids = session.scalars(
        select(Membership.org_id).where(Membership.user_id == parsed_id).order_by(Membership.org_id)
    ).all()
    for org_id in org_ids:
        record_event(
            session,
            org_id=org_id,
            actor_type="operator",
            action="account.unsuspended",
            target_type="user",
            target_id=str(parsed_id),
            metadata={"user_id": str(parsed_id)},
        )
    session.commit()
    logger.warning(
        "Operator unsuspended user_id=%s orgs=%d reason=%r", parsed_id, len(org_ids), cleaned_reason
    )
    print(
        f"Unsuspended user {parsed_id}. Scan schedules turned off by the suspension stay off; "
        "an organization owner must re-enable them."
    )
    return 0


def _all_owners_suspended(session: Session, org_id: int) -> bool:
    """Return True if the organization has no owner left who is not suspended."""
    active_owners = session.scalar(
        select(func.count(Membership.id))
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.org_id == org_id,
            Membership.role == "owner",
            User.suspended_at.is_(None),
        )
    )
    return (active_owners or 0) == 0


def _stop_org_scanning(session: Session, org_id: int) -> tuple[int, int]:
    """Turn off every domain schedule and cancel queued scans in one organization.

    Returns (schedules_turned_off, queued_scans_cancelled). Running scans are left to
    finish (the worker holds their lease).
    """
    schedules = session.execute(
        update(Domain)
        .where(Domain.org_id == org_id, Domain.scan_interval_hours.is_not(None))
        .values(scan_interval_hours=None, next_scan_at=None)
    ).rowcount
    queued_ids = session.scalars(
        select(ScanRun.id)
        .join(Domain, Domain.id == ScanRun.domain_id)
        .where(Domain.org_id == org_id, ScanRun.status == "queued")
        .with_for_update(of=ScanRun)
    ).all()
    if queued_ids:
        session.execute(
            update(ScanRun)
            .where(ScanRun.id.in_(queued_ids))
            .values(
                status="failed",
                finished_at=func.now(),
                error="Cancelled: every owner of this organization is suspended",
            )
        )
        session.execute(
            update(ScanStage)
            .where(ScanStage.scan_run_id.in_(queued_ids), ScanStage.status == "pending")
            .values(
                status="skipped",
                finished_at=func.now(),
                duration_ms=0,
                error="Skipped: scan cancelled",
            )
        )
    return schedules or 0, len(queued_ids)


def build_parser() -> argparse.ArgumentParser:
    """Build administrative CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="asm-admin",
        description="Exposight Administrative Operations",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: move-domain
    move_parser = subparsers.add_parser(
        "move-domain",
        help="Move a domain from the legacy quarantine organization into a target organization",
    )
    move_parser.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain to move",
    )
    move_parser.add_argument(
        "--target-org-id",
        type=int,
        required=True,
        help="ID of the target customer organization",
    )

    # Subcommand: verify-domain
    verify_parser = subparsers.add_parser(
        "verify-domain",
        help="Grant an operator override verification to a domain",
    )
    verify_parser.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain to verify",
    )
    verify_parser.add_argument(
        "--reason",
        type=str,
        required=True,
        help="Mandatory justification for operator verification override",
    )
    verify_parser.add_argument(
        "--expires-in-days",
        type=int,
        default=30,
        help="Duration in days before the override expires (default: 30, max: 90)",
    )

    # Subcommand: revoke-verification
    revoke_parser = subparsers.add_parser(
        "revoke-verification",
        help="Revoke domain verification and reset status to pending",
    )
    revoke_parser.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain whose verification will be revoked",
    )
    revoke_parser.add_argument(
        "--reason",
        type=str,
        required=True,
        help="Mandatory justification for revoking domain verification",
    )

    # Subcommands: suspend-user / unsuspend-user
    for name, help_text in (
        ("suspend-user", "Suspend an account (403 on every request; may stop org schedules)"),
        ("unsuspend-user", "Lift a suspension (schedules stay off until an owner re-enables)"),
    ):
        sub_parser = subparsers.add_parser(name, help=help_text)
        sub_parser.add_argument(
            "--user-id", type=str, required=True, help="User ID (UUID) of the account"
        )
        sub_parser.add_argument(
            "--reason",
            type=str,
            required=True,
            help="Operator-only justification (never shown to users or tenants)",
        )

    return parser


def main(argv: Sequence[str] | None = None, session: Session | None = None) -> int:
    """Main admin CLI entrypoint."""
    install_log_redaction()
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    def _dispatch(sess: Session) -> int:
        if args.command == "move-domain":
            return move_domain(sess, args.domain_id, args.target_org_id)
        elif args.command == "verify-domain":
            return verify_domain(
                sess,
                args.domain_id,
                args.reason,
                expires_in_days=args.expires_in_days,
            )
        elif args.command == "revoke-verification":
            return revoke_verification(sess, args.domain_id, args.reason)
        elif args.command == "suspend-user":
            return suspend_user(sess, args.user_id, args.reason)
        elif args.command == "unsuspend-user":
            return unsuspend_user(sess, args.user_id, args.reason)
        return 0

    if session is not None:
        return _dispatch(session)
    else:
        factory = get_session_factory()
        with factory() as sess:
            return _dispatch(sess)


if __name__ == "__main__":
    sys.exit(main())

