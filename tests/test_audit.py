"""Unit tests for audit logging: validation, redaction, size caps, and target conventions."""

import inspect
import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

import asm.audit as audit_mod
from asm.audit import (
    AUDIT_ACTIONS,
    record_event,
    redact_sensitive_text,
    validate_and_clean_metadata,
)
from asm.db.models import AuditEvent


def test_audit_module_docstring():
    """Verify exact docstring wording as required by specification."""
    doc = inspect.getdoc(audit_mod)
    assert doc is not None
    assert "append-only against the application; the table owner can disable the trigger" in doc


def test_19_audit_actions():
    """Verify exact 19 audit actions (v3.6b added invite.*, v3.6c added account.*)."""
    expected_actions = {
        "org.created",
        "membership.added",
        "membership.role_changed",
        "membership.removed",
        "domain.created",
        "domain.schedule_changed",
        "domain.alerts_changed",
        "verification.checked",
        "verification.rotated",
        "verification.operator_granted",
        "verification.operator_revoked",
        "verification.lapsed",
        "verification.override_expired",
        "domain.moved",
        "scan.queued",
        "invite.created",
        "invite.revoked",
        "account.suspended",
        "account.unsuspended",
    }
    assert AUDIT_ACTIONS == expected_actions
    assert len(AUDIT_ACTIONS) == 19


def test_redact_sensitive_text():
    """Verify email and IP masking as [redacted]."""
    text = (
        "Created by admin@example.com from 192.168.1.100 and "
        "2001:db8:85a3:8d3:1319:8a2e:370:7348"
    )
    redacted = redact_sensitive_text(text)
    assert "admin@example.com" not in redacted
    assert "192.168.1.100" not in redacted
    assert "2001:db8:85a3:8d3:1319:8a2e:370:7348" not in redacted
    assert "[redacted]" in redacted


def test_metadata_redaction_for_free_text():
    """Verify org.created name and operator reason redact email and IP without raising."""
    meta = validate_and_clean_metadata(
        "org.created",
        {"name": "Org of user@company.com at 10.0.0.1"},
    )
    assert meta["name"] == "Org of [redacted] at [redacted]"

    meta_op = validate_and_clean_metadata(
        "verification.operator_granted",
        {
            "reason": "Approved by security-ops@domain.org from 172.16.0.5",
            "expires_in_days": 30,
            "verification_expires_at": None,
        },
    )
    assert meta_op["reason"] == "Approved by [redacted] from [redacted]"


def test_metadata_unknown_key_rejected():
    """Unknown keys in metadata raise ValueError."""
    with pytest.raises(ValueError, match="Disallowed metadata key"):
        validate_and_clean_metadata("verification.rotated", {"extra": "field"})

    with pytest.raises(ValueError, match="Disallowed metadata key"):
        validate_and_clean_metadata("domain.created", {"name": "test.com", "unknown_key": 123})


def test_metadata_wrong_type_rejected():
    """Wrong types in metadata raise ValueError."""
    with pytest.raises(ValueError, match="invalid type"):
        validate_and_clean_metadata("domain.created", {"name": 12345})

    with pytest.raises(ValueError, match="expected int but got bool"):
        validate_and_clean_metadata(
            "domain.schedule_changed",
            {"old_interval_hours": True, "new_interval_hours": 24},
        )


def test_metadata_size_cap():
    """Metadata exceeding 2048 bytes raises ValueError."""
    large_string = "a" * 2050
    with pytest.raises(ValueError, match="exceeds maximum allowed size of 2048 bytes"):
        validate_and_clean_metadata("domain.created", {"name": large_string})


def test_verification_lapsed_strict_outcome():
    """verification.lapsed outcome must strictly be 'absent'."""
    with pytest.raises(ValueError, match="outcome must be 'absent'"):
        validate_and_clean_metadata(
            "verification.lapsed",
            {"consecutive_misses": 2, "outcome": "match"},
        )


def test_target_type_enforcement():
    """record_event enforces specific target_type per action."""
    mock_session = MagicMock(spec=Session)

    with pytest.raises(ValueError, match="requires target_type='domain'"):
        record_event(
            mock_session,
            org_id=1,
            actor_type="user",
            action="domain.created",
            target_type="invalid",
            target_id="1",
            metadata={"name": "test.com"},
        )

    with pytest.raises(ValueError, match="requires target_type='org'"):
        record_event(
            mock_session,
            org_id=1,
            actor_type="user",
            action="org.created",
            target_type="domain",
            target_id="1",
            metadata={"name": "Acme Corp"},
        )

    with pytest.raises(ValueError, match="requires target_type='membership'"):
        record_event(
            mock_session,
            org_id=1,
            actor_type="user",
            action="membership.added",
            target_type="org",
            target_id="1",
            metadata={"user_id": str(uuid.uuid4()), "role": "viewer"},
        )


def test_record_event_uncommitted_session():
    """record_event adds to session and never commits or flushes."""
    mock_session = MagicMock(spec=Session)

    user_id = uuid.uuid4()
    ev = record_event(
        mock_session,
        org_id=42,
        actor_type="user",
        actor_user_id=user_id,
        action="domain.created",
        target_type="domain",
        target_id="101",
        metadata={"name": "example.com"},
    )

    mock_session.add.assert_called_once_with(ev)
    mock_session.commit.assert_not_called()
    mock_session.flush.assert_not_called()
    assert isinstance(ev, AuditEvent)
    assert ev.org_id == 42
    assert ev.actor_type == "user"
    assert ev.actor_user_id == user_id
    assert ev.action == "domain.created"
    assert ev.target_type == "domain"
    assert ev.target_id == "101"
    assert ev.metadata_ == {"name": "example.com"}


def test_freetext_truncation_to_500_chars():
    """A 5000-character reason is stored truncated to 500 chars, and record_event does not raise."""
    mock_session = MagicMock(spec=Session)
    long_reason = "X" * 5000

    ev = record_event(
        mock_session,
        org_id=1,
        actor_type="operator",
        action="verification.operator_granted",
        target_type="domain",
        target_id="10",
        metadata={
            "reason": long_reason,
            "expires_in_days": 30,
            "verification_expires_at": None,
        },
    )
    assert len(ev.metadata_["reason"]) == 500
    assert ev.metadata_["reason"] == "X" * 500

