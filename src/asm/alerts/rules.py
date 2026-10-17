"""Pure trigger rules for attack surface change alerts."""

from __future__ import annotations

from typing import Any

from asm.scoring import TIER_RANK


def should_trigger_alerts(
    alerts_enabled: bool,
    alert_emails: list[str] | None,
    verified: bool,
    alert_min_severity: str,
    change_summary: dict[str, Any] | None,
    changes: list[dict[str, Any]] | None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Pure decision function: determine whether alert notifications should be queued.

    Rules:
    1. Domain must have alerts_enabled == True and 1..5 alert_emails configured.
    2. Domain must be verified.
    3. change_summary['status'] must be strictly 'computed'.
       - Never triggers on 'baseline' (first scan).
       - Never triggers on 'failed' (detection error).
       - Never triggers on 'skipped'.
    4. There must be >= 1 change with category == 'exposure' and
       severity >= domain.alert_min_severity.
       - Summary changes (category == 'summary') NEVER trigger alerts.
       - Remediation changes (category == 'remediation') NEVER trigger alerts.

    Returns:
        (should_alert, triggering_exposure_changes)
    """
    if not alerts_enabled or not alert_emails or not verified:
        return False, []

    if not change_summary or change_summary.get("status") != "computed":
        return False, []

    if not changes:
        return False, []

    min_rank = TIER_RANK.get(alert_min_severity, TIER_RANK["MEDIUM"])

    triggering = [
        ch
        for ch in changes
        if ch.get("category") == "exposure"
        and TIER_RANK.get(ch.get("severity", "INFO"), 0) >= min_rank
    ]

    if not triggering:
        return False, []

    # Sort triggering changes: highest severity first, then asset asc, then change_type asc
    triggering.sort(
        key=lambda ch: (
            -TIER_RANK.get(ch.get("severity", "INFO"), 0),
            ch.get("asset", ""),
            ch.get("change_type", ""),
        )
    )

    return True, triggering


VERIFICATION_STATUS_SUBJECTS: frozenset[str] = frozenset({
    "domain verification revoked: monitoring paused",
    "domain verification expired: monitoring paused",
    "domain verification lapsed: monitoring paused",
})


def is_verification_status_notification(scan_run_id: int | None, subject: str) -> bool:
    """Return True only if notification matches known verification status alerts.

    In Exposight's current schema without a dedicated notification_type column,
    verification-loss notices are identified strictly by:
    1. scan_run_id is None (domain-level outbox alert), AND
    2. subject matching one of the exact canonical production subjects:
       - 'Domain verification revoked: monitoring paused'
       - 'Domain verification expired: monitoring paused'
       - 'Domain verification lapsed: monitoring paused'

    Any row with scan_run_id is not None is a scan-result notification and MUST
    require active verification regardless of its subject. Any domain-level alert
    (scan_run_id is None) with an unknown, misleading, or unrelated subject
    fails safe and does NOT receive the verification exemption.
    """
    if scan_run_id is not None:
        return False
    clean_subj = (subject or "").strip().lower()
    return clean_subj in VERIFICATION_STATUS_SUBJECTS


def check_notification_delivery_authorization(
    domain_exists: bool,
    alerts_enabled: bool,
    configured_alert_emails: list[str] | None,
    recipient: str,
    all_owners_suspended: bool,
    is_verified: bool,
    is_verification_notice: bool,
) -> tuple[bool, str | None]:
    """Pure decision function: determine whether a queued notification is authorized for delivery.

    Rules:
    1. Domain must exist.
    2. Domain alerts must be enabled (alerts_enabled == True).
    3. Notification recipient must be present in configured domain.alert_emails (case-insensitive).
    4. Organization must have at least one active (non-suspended) owner.
    5. For scan-result notifications (not a verification notice), domain verification
       must be active. Verification-expiry/revocation notices may send while verification
       is inactive, provided rules 1-4 pass.

    Returns:
        (authorized, suppression_reason)
    """
    if not domain_exists:
        return False, "Domain no longer exists"

    if not alerts_enabled:
        return False, "Domain alerts are disabled"

    recipient_clean = (recipient or "").strip().lower()
    allowed_recipients = {e.strip().lower() for e in (configured_alert_emails or [])}
    if not recipient_clean or recipient_clean not in allowed_recipients:
        return False, "Recipient is no longer configured for domain alerts"

    if all_owners_suspended:
        return False, "All organization owners are suspended"

    if not is_verification_notice and not is_verified:
        return False, "Domain verification is inactive or expired"

    return True, None
