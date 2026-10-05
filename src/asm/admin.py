"""Administrative CLI operations for ASM SaaS."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.audit import record_event
from asm.db.models import Domain, Organization
from asm.db.session import get_session_factory
from asm.verification import queue_domain_alert

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

    old_org_id = domain.org_id
    domain.org_id = target_org_id

    # Record dual events in the same transaction
    record_event(
        session,
        org_id=old_org_id,
        actor_type="operator",
        action="domain.moved",
        target_type="domain",
        target_id=str(domain_id),
        metadata={"to_org_id": target_org_id, "reason": f"Moved to org {target_org_id}"},
    )
    record_event(
        session,
        org_id=target_org_id,
        actor_type="operator",
        action="domain.moved",
        target_type="domain",
        target_id=str(domain_id),
        metadata={"from_org_id": old_org_id, "reason": f"Moved from org {old_org_id}"},
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

    return parser


def main(argv: Sequence[str] | None = None, session: Session | None = None) -> int:
    """Main admin CLI entrypoint."""
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
        return 0

    if session is not None:
        return _dispatch(session)
    else:
        factory = get_session_factory()
        with factory() as sess:
            return _dispatch(sess)


if __name__ == "__main__":
    sys.exit(main())

