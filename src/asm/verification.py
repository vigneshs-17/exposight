"""Domain ownership verification engine via DNS TXT records."""

from __future__ import annotations

import enum
import logging
import random
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import dns.exception
import dns.resolver

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from asm.db.models import Domain

logger = logging.getLogger("asm.verification")

# Minimum cooldown between on-demand DNS verification check requests for a domain (seconds)
VERIFICATION_CHECK_COOLDOWN_SECONDS: int = 30


class VerificationOutcome(enum.Enum):
    """Classification of a DNS TXT verification check attempt."""

    MATCH = "match"  # TXT record present and matches the token exactly
    ABSENT = "absent"  # Definite absence (NXDOMAIN, NoAnswer, or non-matching token)
    UNKNOWN = "unknown"  # Indeterminate (timeout, SERVFAIL, temporary network error)


def generate_verification_token() -> str:
    """Generate a high-entropy server-side verification token."""
    return secrets.token_urlsafe(32)


def get_verification_record_name(domain_name: str) -> str:
    """Return the designated DNS TXT label for domain verification."""
    return f"_asm-verify.{domain_name.strip().rstrip('.')}"


def get_expected_record_value(token: str) -> str:
    """Return the expected TXT record payload value for a verification token."""
    return f"asm-verify={token.strip()}"


def check_dns_txt_verification(
    domain_name: str,
    expected_token: str,
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[VerificationOutcome, str | None]:
    """Query DNS TXT records at _asm-verify.<domain> and evaluate ownership proof.

    Rules:
    - Joins multi-string TXT records (RFC 1035 chunking) before comparing.
    - Exact match only.
    - Definite absence (NXDOMAIN, NoAnswer, or record present without matching token) -> ABSENT.
    - Transient or server errors (Timeout, SERVFAIL, NoNameservers) -> UNKNOWN.

    Args:
        domain_name: Target apex or monitored domain name.
        expected_token: The expected random verification token string.
        resolver: Optional configured dnspython Resolver instance (for testing/mocking).

    Returns:
        A tuple of (VerificationOutcome, detail_message).
    """
    lookup_name = get_verification_record_name(domain_name)
    expected_value = get_expected_record_value(expected_token)

    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 3.0

    try:
        answers = resolver.resolve(lookup_name, "TXT")
        found_txts: list[str] = []
        for rdata in answers:
            # Join multiple string segments within the same TXT record per RFC 1035
            joined = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            found_txts.append(joined)
            if joined == expected_value:
                return VerificationOutcome.MATCH, f"Matching TXT record verified at {lookup_name}"

        return (
            VerificationOutcome.ABSENT,
            f"TXT record present at {lookup_name} but does not match expected token",
        )

    except dns.resolver.NXDOMAIN:
        return VerificationOutcome.ABSENT, f"Domain name {lookup_name} does not exist (NXDOMAIN)"

    except dns.resolver.NoAnswer:
        return VerificationOutcome.ABSENT, f"No TXT records found at {lookup_name} (NoAnswer)"

    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
        return VerificationOutcome.UNKNOWN, f"DNS query timed out resolving {lookup_name}: {exc}"

    except dns.resolver.NoNameservers as exc:
        return (
            VerificationOutcome.UNKNOWN,
            f"DNS resolution failed (SERVFAIL or unreachable nameservers) for {lookup_name}: {exc}",
        )

    except dns.exception.DNSException as exc:
        return VerificationOutcome.UNKNOWN, f"DNS exception resolving {lookup_name}: {exc}"

    except Exception as exc:
        return (
            VerificationOutcome.UNKNOWN,
            f"Unexpected error during DNS verification for {lookup_name}: {exc}",
        )


def apply_check_outcome(
    domain: Domain,
    outcome: VerificationOutcome,
    now: datetime,
) -> bool:
    """Apply DNS verification check outcome to domain verification posture.

    Rules:
    - MATCH: status=verified, method=dns_txt, verification_expires_at=None,
      verification_reason=None, consecutive_misses=0, next_reverification_at=now+24h±30min.
      Set verified_at=now unless the domain was already verified via dns_txt.
    - ABSENT, verified + dns_txt: misses+=1; misses>=2 -> status=lapsed,
      next_reverification_at=None; else next_reverification_at=now+1h(+0..5min).
    - ABSENT, verified + operator: no change (operator domains leave only by expiry or revoke).
    - ABSENT, pending or lapsed: no change.
    - UNKNOWN: never changes status or misses; if verified + dns_txt,
      next_reverification_at=now+1h(+0..5min).

    Returns:
        True ONLY when the domain has just transitioned to 'lapsed' as a result of this check.
        Returns False in all other cases.
    """
    if outcome == VerificationOutcome.MATCH:
        was_verified_dns_txt = (
            domain.verification_status == "verified"
            and domain.verification_method == "dns_txt"
            and domain.verified_at is not None
        )
        domain.verification_status = "verified"
        domain.verification_method = "dns_txt"
        domain.verification_expires_at = None
        domain.verification_reason = None
        domain.consecutive_misses = 0
        jitter_seconds = random.randint(-1800, 1800)  # jitter, not a secret  # nosec B311
        domain.next_reverification_at = now + timedelta(hours=24, seconds=jitter_seconds)
        if not was_verified_dns_txt:
            domain.verified_at = now
        return False

    elif outcome == VerificationOutcome.ABSENT:
        if domain.verification_status == "verified":
            if domain.verification_method == "dns_txt":
                domain.consecutive_misses += 1
                if domain.consecutive_misses >= 2:
                    domain.verification_status = "lapsed"
                    domain.next_reverification_at = None
                    return True
                else:
                    jitter_fast = random.randint(0, 300)  # jitter, not a secret  # nosec B311
                    domain.next_reverification_at = now + timedelta(hours=1, seconds=jitter_fast)
                    return False
            elif domain.verification_method == "operator":
                # Operator domains leave only by expiry or revoke
                return False
        # pending or lapsed: no change
        return False

    elif outcome == VerificationOutcome.UNKNOWN:
        # UNKNOWN: never changes status or misses; if verified + dns_txt, reschedule fast retry
        if domain.verification_status == "verified" and domain.verification_method == "dns_txt":
            jitter_unknown = random.randint(0, 300)  # jitter, not a secret  # nosec B311
            domain.next_reverification_at = now + timedelta(hours=1, seconds=jitter_unknown)
        return False

    return False


def queue_domain_alert(
    session: Session,
    domain: Domain,
    subject: str,
    body: str,
) -> int:
    """Queue domain-level alert notification rows in the outbox.

    Returns the number of alert notification rows queued; returns 0 if alerts
    are disabled for the domain or no alert emails are configured.
    """
    if not domain.alerts_enabled or not domain.alert_emails:
        return 0

    from asm.db.models import AlertNotification

    now_utc = datetime.now(UTC)
    count = 0
    for email in domain.alert_emails:
        session.add(
            AlertNotification(
                domain_id=domain.id,
                scan_run_id=None,
                recipient=email,
                subject=subject,
                body=body,
                status="pending",
                next_attempt_at=now_utc,
            )
        )
        count += 1
    return count

