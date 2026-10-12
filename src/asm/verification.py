"""Domain ownership verification engine via DNS TXT records."""

from __future__ import annotations

import enum
import logging
import random
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import dns.exception
import dns.flags
import dns.resolver

from asm.config import get_settings

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


# Current record (E-4): an application-specific label so the record cannot be confused
# with another product's verification record.
RECORD_LABEL = "_exposight-challenge"
RECORD_VALUE_PREFIX = "exposight-verify="
# Legacy record (before E-4). Still accepted by the checker so domains verified under it
# do not lapse; never shown to users.
LEGACY_RECORD_LABEL = "_asm-verify"
LEGACY_RECORD_VALUE_PREFIX = "asm-verify="

# Per query; a check makes at most 2 resolvers x 2 labels sequential queries.
# ponytail: sequential worst case ~12 s per check; query in parallel if that ever matters.
VERIFICATION_DNS_TIMEOUT_SECONDS: float = 3.0


def get_verification_record_name(domain_name: str) -> str:
    """Return the designated DNS TXT label for domain verification."""
    return f"{RECORD_LABEL}.{domain_name.strip().rstrip('.')}"


def get_expected_record_value(token: str) -> str:
    """Return the expected TXT record payload value for a verification token."""
    return f"{RECORD_VALUE_PREFIX}{token.strip()}"


def _accepted_records(domain_name: str, token: str) -> list[tuple[str, str]]:
    """(label, value) pairs the checker accepts: current first, then legacy."""
    name = domain_name.strip().rstrip(".")
    return [
        (get_verification_record_name(name), get_expected_record_value(token)),
        (f"{LEGACY_RECORD_LABEL}.{name}", f"{LEGACY_RECORD_VALUE_PREFIX}{token.strip()}"),
    ]


def build_validating_resolver(ip: str) -> dns.resolver.Resolver:
    """Resolver that asks one explicit public resolver for DNSSEC-validated answers.

    configure=False: never reads the host's resolver configuration (on Azure that is
    168.63.129.16, which the worker cannot reach by design).
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    resolver.timeout = VERIFICATION_DNS_TIMEOUT_SECONDS
    resolver.lifetime = VERIFICATION_DNS_TIMEOUT_SECONDS
    resolver.use_edns(0, dns.flags.DO, 1232)
    resolver.flags = dns.flags.RD | dns.flags.AD
    return resolver


def _check_one_resolver(
    resolver: dns.resolver.Resolver, records: list[tuple[str, str]]
) -> tuple[VerificationOutcome, bool, str]:
    """Check every accepted label at one resolver.

    Returns (outcome, authenticated, detail). MATCH if any label holds its exact value
    (authenticated = the answer had the AD bit); ABSENT only if every label is
    definitively absent or holds no matching value; otherwise UNKNOWN.
    """
    server = resolver.nameservers[0] if resolver.nameservers else "resolver"
    error: str | None = None
    for lookup_name, expected_value in records:
        try:
            answers = resolver.resolve(lookup_name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            error = f"{server}: DNS query timed out resolving {lookup_name}: {exc}"
            continue
        except dns.resolver.NoNameservers as exc:
            error = f"{server}: SERVFAIL or unreachable nameserver for {lookup_name}: {exc}"
            continue
        except Exception as exc:
            error = f"{server}: DNS error resolving {lookup_name}: {exc}"
            continue
        for rdata in answers:
            # Join multiple string segments within the same TXT record per RFC 1035
            joined = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            if joined == expected_value:
                authenticated = bool(answers.response.flags & dns.flags.AD)
                return (
                    VerificationOutcome.MATCH,
                    authenticated,
                    f"Matching TXT record verified at {lookup_name}",
                )
    if error is not None:
        return VerificationOutcome.UNKNOWN, False, error
    return (
        VerificationOutcome.ABSENT,
        False,
        f"{server}: no TXT record matching the expected token at {records[0][0]}",
    )


def check_dns_txt_verification(
    domain_name: str,
    expected_token: str,
    resolvers: list[dns.resolver.Resolver] | None = None,
) -> tuple[VerificationOutcome, str | None]:
    """Query the verification TXT labels at every configured resolver and decide.

    Accepted: _exposight-challenge.<domain> = exposight-verify=<token>, or the legacy
    _asm-verify.<domain> = asm-verify=<token>. Multi-string TXT records are joined
    (RFC 1035 chunking); exact match only.

    Decision:
    - A matching answer with the AD bit (DNSSEC-validated) from any resolver -> MATCH.
    - Otherwise every resolver must return a match -> MATCH.
    - Every resolver definitively absent (NXDOMAIN, NoAnswer, no matching value) -> ABSENT.
    - Anything else (one matches and another does not, which may be propagation, or any
      timeout / SERVFAIL / error) -> UNKNOWN, which changes no status.

    Args:
        domain_name: Target apex or monitored domain name.
        expected_token: The expected random verification token string.
        resolvers: Resolver instances (tests inject fakes). Default: one validating
            resolver per address in the VERIFICATION_RESOLVERS setting.

    Returns:
        A tuple of (VerificationOutcome, detail_message).
    """
    records = _accepted_records(domain_name, expected_token)
    if resolvers is None:
        resolvers = [build_validating_resolver(ip) for ip in get_settings().verification_resolvers]

    results = [_check_one_resolver(resolver, records) for resolver in resolvers]
    for outcome, authenticated, detail in results:
        if outcome == VerificationOutcome.MATCH and authenticated:
            return VerificationOutcome.MATCH, f"{detail} (DNSSEC-validated)"

    outcomes = {outcome for outcome, _, _ in results}
    if outcomes == {VerificationOutcome.MATCH}:
        return VerificationOutcome.MATCH, f"{results[0][2]} (all {len(results)} resolvers agree)"
    if outcomes == {VerificationOutcome.ABSENT}:
        return VerificationOutcome.ABSENT, results[0][2]
    if VerificationOutcome.MATCH in outcomes and VerificationOutcome.UNKNOWN not in outcomes:
        return (
            VerificationOutcome.UNKNOWN,
            "Resolvers disagree (record may still be propagating): "
            + "; ".join(detail for _, _, detail in results),
        )
    return VerificationOutcome.UNKNOWN, "; ".join(detail for _, _, detail in results) or None


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

