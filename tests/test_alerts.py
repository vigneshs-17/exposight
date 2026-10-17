"""Unit tests for alert digest building, pure trigger rules, and email validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asm.alerts.digest import build_alert_digest, sanitize_body_field, sanitize_header_field
from asm.alerts.rules import (
    check_notification_delivery_authorization,
    is_verification_status_notification,
    should_trigger_alerts,
)
from asm.api.schemas import DomainAlertsUpdate


def test_sanitize_header_field_strips_crlf_and_caps_length():
    """Header fields must have CR, LF, and control chars stripped and length capped."""
    dirty = "example.com\r\nSubject: Injected\x00Header"
    clean = sanitize_header_field(dirty, max_len=50)
    assert "\r" not in clean
    assert "\n" not in clean
    assert "\x00" not in clean
    assert clean == "example.comSubject: InjectedHeader"

    # Length capping
    long_str = "a" * 100
    capped = sanitize_header_field(long_str, max_len=20)
    assert len(capped) == 20


def test_sanitize_body_field_strips_control_chars_and_truncates():
    """Body fields must have dangerous control characters stripped and truncated with ellipsis."""
    assert sanitize_body_field(None) == ""
    dirty = "Dangerous\x00\x07Text"
    assert sanitize_body_field(dirty) == "DangerousText"

    long_text = "x" * 250
    truncated = sanitize_body_field(long_text, max_len=200)
    assert len(truncated) == 200
    assert truncated.endswith("...")


def test_build_alert_digest_formatting_and_ordering():
    """Digest must order exposures highest severity first and strip CR/LF from subject."""
    changes = [
        {
            "change_type": "PORT_NEWLY_OPEN",
            "category": "exposure",
            "severity": "LOW",
            "asset": "low.example.com",
            "detail": "port 8080 open",
            "evidence": "portscan",
        },
        {
            "change_type": "PORT_NEWLY_OPEN",
            "category": "exposure",
            "severity": "CRITICAL",
            "asset": "db.example.com",
            "detail": "PostgreSQL exposed\r\nwith banner",
            "evidence": "portscan",
        },
        {
            "change_type": "CERTIFICATE_BECAME_EXPIRED",
            "category": "exposure",
            "severity": "HIGH",
            "asset": "api.example.com",
            "detail": "Certificate expired",
            "evidence": "inspect",
        },
        {
            "change_type": "DOMAIN_RISK_BAND_INCREASED",
            "category": "summary",
            "severity": "HIGH",
            "asset": "example.com",
            "detail": "",
            "evidence": "score",
        },
    ]

    triggering = [changes[0], changes[1], changes[2]]  # LOW, CRITICAL, HIGH

    subject, body = build_alert_digest(
        domain_name="example.com\r\nBcc: evil@attacker.com",
        scan_run_id=42,
        changes=changes,
        triggering_changes=triggering,
    )

    # Subject checks: no CR/LF, highest severity is CRITICAL, count is 3
    assert "\r" not in subject
    assert "\n" not in subject
    expected_subject_part = (
        "[Exposight] CRITICAL: 3 new exposures on example.comBcc: evil@attacker.com"
    )
    assert expected_subject_part in subject

    # Body checks: plain text, summaries included, ordered CRITICAL -> HIGH -> LOW
    assert "Scan Run ID: 42" in body
    assert "- CRITICAL: 1" in body
    assert "- HIGH:     2" in body  # 1 exposure + 1 summary
    assert "- LOW:      1" in body

    # Ordering in body: CRITICAL appears before HIGH, HIGH appears before LOW
    crit_pos = body.find("Severity: CRITICAL")
    high_pos = body.find("Severity: HIGH")
    low_pos = body.find("Severity: LOW")
    assert 0 < crit_pos < high_pos < low_pos

    # Untrusted details in body have control chars sanitized
    assert "\r\nwith banner" not in body


def test_should_trigger_alerts_pure_rules():
    """Alerts trigger only on 'computed' status with exposure changes at/above threshold."""
    changes = [
        {
            "category": "exposure",
            "severity": "LOW",
            "asset": "sub.example.com",
            "change_type": "PORT_NEWLY_OPEN",
        },
        {
            "category": "exposure",
            "severity": "HIGH",
            "asset": "api.example.com",
            "change_type": "CERT_EXPIRED",
        },
        {
            "category": "summary",
            "severity": "CRITICAL",
            "asset": "example.com",
            "change_type": "DOMAIN_RISK_BAND_INCREASED",
        },
        {
            "category": "remediation",
            "severity": "INFO",
            "asset": "old.example.com",
            "change_type": "PORT_CLOSED",
        },
    ]

    # 1. Disabled alerts -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=False,
        alert_emails=["ops@example.com"],
        verified=True,
        alert_min_severity="MEDIUM",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert not should
    assert trig == []

    # 2. Empty emails -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=[],
        verified=True,
        alert_min_severity="MEDIUM",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert not should

    # 3. Unverified domain -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        verified=False,
        alert_min_severity="MEDIUM",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert not should

    # 4. Status baseline -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        verified=True,
        alert_min_severity="MEDIUM",
        change_summary={"status": "baseline"},
        changes=changes,
    )
    assert not should

    # 5. Status failed -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        verified=True,
        alert_min_severity="MEDIUM",
        change_summary={"status": "failed"},
        changes=changes,
    )
    assert not should

    # 6. Threshold MEDIUM matches HIGH exposure, ignores LOW exposure, ignores summary/remediation
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        verified=True,
        alert_min_severity="MEDIUM",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert should
    assert len(trig) == 1
    assert trig[0]["severity"] == "HIGH"
    assert trig[0]["asset"] == "api.example.com"

    # 7. Threshold CRITICAL: none match exposure -> False
    should, trig = should_trigger_alerts(
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        verified=True,
        alert_min_severity="CRITICAL",
        change_summary={"status": "computed"},
        changes=changes,
    )
    assert not should
    assert trig == []


def test_domain_alerts_schema_validation():
    """DomainAlertsUpdate validates email count, formats, and rejects CR/LF."""
    # Valid enabled with 1-5 emails
    payload = DomainAlertsUpdate(
        alerts_enabled=True,
        alert_emails=["alice@example.com", "bob@example.com"],
        alert_min_severity="HIGH",
    )
    assert payload.alerts_enabled is True
    assert len(payload.alert_emails) == 2

    # Valid disabled with empty emails
    payload_dis = DomainAlertsUpdate(alerts_enabled=False, alert_emails=[])
    assert payload_dis.alerts_enabled is False
    assert payload_dis.alert_emails == []

    # Invalid: enabled with 0 emails
    with pytest.raises(ValidationError) as exc:
        DomainAlertsUpdate(alerts_enabled=True, alert_emails=[])
    assert "between 1 and 5 alert_emails must be provided" in str(exc.value)

    # Invalid: enabled with >5 emails
    with pytest.raises(ValidationError) as exc:
        DomainAlertsUpdate(
            alerts_enabled=True,
            alert_emails=[f"user{i}@example.com" for i in range(6)],
        )
    assert "between 1 and 5 alert_emails must be provided" in str(exc.value)

    # Invalid: CR/LF in email address
    with pytest.raises(ValidationError):
        DomainAlertsUpdate(
            alerts_enabled=True,
            alert_emails=["admin@example.com\r\nBcc: evil@attacker.com"],
        )

    # Invalid: malformed email
    with pytest.raises(ValidationError):
        DomainAlertsUpdate(
            alerts_enabled=True,
            alert_emails=["not-an-email"],
        )

    # Invalid severity
    with pytest.raises(ValidationError):
        DomainAlertsUpdate(
            alerts_enabled=False,
            alert_min_severity="INVALID_SEVERITY",
        )


def test_is_verification_status_notification():
    """Verify classification of notification types."""
    # Scan result notification with run ID is never verification status
    assert not is_verification_status_notification(
        42, "Domain verification revoked: monitoring paused"
    )
    assert not is_verification_status_notification(
        1, "[Exposight] CRITICAL: 1 new exposure on test.com"
    )

    # Domain lapse / revocation notices have scan_run_id=None and verification subject
    assert is_verification_status_notification(
        None, "Domain verification revoked: monitoring paused"
    )
    assert is_verification_status_notification(
        None, "Domain verification expired: monitoring paused"
    )
    assert is_verification_status_notification(
        None, "Domain verification lapsed: monitoring paused"
    )

    # Misleading prefixes and substrings fail safe
    assert not is_verification_status_notification(None, "Domain verification: 2 open ports")
    assert not is_verification_status_notification(None, "Domain verification alert: port 22 open")
    assert not is_verification_status_notification(None, "Verification completed: scan details")
    assert not is_verification_status_notification(None, "Domain verification bypass attempt")
    assert not is_verification_status_notification(None, "Unrelated domain alert")

    # Scan-result row with exact verification subject must still fail (scan rows never exempted)
    assert not is_verification_status_notification(
        99, "Domain verification lapsed: monitoring paused"
    )
    assert not is_verification_status_notification(
        99, "Domain verification revoked: monitoring paused"
    )


def test_check_notification_delivery_authorization_pure_rules():
    """Test all authorization rules for outbox notification delivery."""
    # 1. Domain deleted / does not exist
    auth, reason = check_notification_delivery_authorization(
        domain_exists=False,
        alerts_enabled=True,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=True,
        is_verification_notice=False,
    )
    assert not auth
    assert "Domain no longer exists" in reason

    # 2. Alerts disabled
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=False,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=True,
        is_verification_notice=False,
    )
    assert not auth
    assert "Domain alerts are disabled" in reason

    # 3. Recipient removed or mismatch (case-insensitive check)
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["other@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=True,
        is_verification_notice=False,
    )
    assert not auth
    assert "Recipient is no longer configured" in reason

    # 4. Case-insensitive matching succeeds
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["Ops@Test.COM"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=True,
        is_verification_notice=False,
    )
    assert auth
    assert reason is None

    # 5. All owners suspended
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=True,
        is_verified=True,
        is_verification_notice=False,
    )
    assert not auth
    assert "All organization owners are suspended" in reason

    # 6. Scan result notice with inactive/expired verification -> suppressed
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=False,
        is_verification_notice=False,
    )
    assert not auth
    assert "Domain verification is inactive or expired" in reason

    # 7. Verification notice with inactive verification -> authorized!
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=False,
        is_verified=False,
        is_verification_notice=True,
    )
    assert auth
    assert reason is None

    # 8. Verification notice with suspended owners -> suppressed!
    auth, reason = check_notification_delivery_authorization(
        domain_exists=True,
        alerts_enabled=True,
        configured_alert_emails=["ops@test.com"],
        recipient="ops@test.com",
        all_owners_suspended=True,
        is_verified=False,
        is_verification_notice=True,
    )
    assert not auth
    assert "All organization owners are suspended" in reason
