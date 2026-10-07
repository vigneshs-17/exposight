"""Audit logging for Exposight.

append-only against the application; the table owner can disable the trigger
"""

import json
import re
import uuid
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from asm.db.models import AuditEvent, User

ALLOWED_ACTOR_TYPES = {"user", "operator", "system"}

# Regex patterns for redacting email addresses and IP addresses in free-text fields
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# Action-specific metadata key and type definitions
# Format: action -> dict of allowed_keys -> (allowed_types, is_free_text_to_redact)
ACTION_METADATA_SPECS: dict[str, dict[str, tuple[tuple[type, ...], bool]]] = {
    "org.created": {
        "name": ((str,), True),
    },
    # v3.6c B-5: the org row stays as a tombstone so its audit events survive.
    "org.deleted": {
        "domains_deleted": ((int,), False),
        "members_removed": ((int,), False),
        "invites_deleted": ((int,), False),
        "schedules_cancelled": ((int,), False),
        "queued_scans_cancelled": ((int,), False),
    },
    "membership.added": {
        "user_id": ((str, uuid.UUID), False),
        "role": ((str,), False),
        "via": ((str,), False),
        "invite_id": ((int,), False),
    },
    # Invitee email addresses are deliberately not recorded (no PII in the audit log).
    "invite.created": {
        "role": ((str,), False),
        "expires_at": ((str,), False),
    },
    "invite.revoked": {
        "role": ((str,), False),
    },
    # Operator suspensions. The operator's reason is never stored here: tenants can
    # read their organization's audit log.
    "account.suspended": {
        "user_id": ((str, uuid.UUID), False),
        "schedules_cancelled": ((int,), False),
        "queued_scans_cancelled": ((int,), False),
    },
    "account.unsuspended": {
        "user_id": ((str, uuid.UUID), False),
    },
    # Self-service account deletion (DELETE /me): one event per organization the user left.
    "account.deleted": {
        "user_id": ((str, uuid.UUID), False),
        "role": ((str,), False),
    },
    "membership.role_changed": {
        "user_id": ((str, uuid.UUID), False),
        "old_role": ((str,), False),
        "new_role": ((str,), False),
    },
    "membership.removed": {
        "user_id": ((str, uuid.UUID), False),
        "role": ((str,), False),
    },
    "domain.created": {
        "name": ((str,), False),
    },
    "domain.schedule_changed": {
        "old_interval_hours": ((int, type(None)), False),
        "new_interval_hours": ((int, type(None)), False),
    },
    "domain.alerts_changed": {
        "old_enabled": ((bool,), False),
        "new_enabled": ((bool,), False),
        "old_min_severity": ((str, type(None)), False),
        "new_min_severity": ((str, type(None)), False),
        "old_recipient_count": ((int,), False),
        "new_recipient_count": ((int,), False),
        "recipients_changed": ((bool,), False),
    },
    "verification.checked": {
        "outcome": ((str,), False),
        "consecutive_misses": ((int,), False),
    },
    "verification.rotated": {},
    "verification.operator_granted": {
        "reason": ((str,), True),
        "expires_in_days": ((int,), False),
        "verification_expires_at": ((str, type(None)), False),
    },
    "verification.operator_revoked": {
        "reason": ((str,), True),
    },
    "verification.lapsed": {
        "consecutive_misses": ((int,), False),
        "outcome": ((str,), False),
    },
    "verification.override_expired": {
        "expired_at": ((str, type(None)), False),
    },
    "domain.moved": {
        "reason": ((str,), True),
        "to_org_id": ((int, str), False),
        "from_org_id": ((int, str), False),
        "verification_reset": ((bool,), False),
        "alerts_reset": ((bool,), False),
        "schedule_reset": ((bool,), False),
    },
    "scan.queued": {
        "scan_run_id": ((int,), False),
        "trigger": ((str,), False),
    },
}

AUDIT_ACTIONS = set(ACTION_METADATA_SPECS.keys())


def recipients_changed(old_emails: list[str], new_emails: list[str]) -> bool:
    """Return True if the set of alert recipients changed (case-insensitive, order ignored).

    Used so the audit log records THAT recipients changed without storing addresses.
    """
    return {e.strip().lower() for e in old_emails} != {e.strip().lower() for e in new_emails}


def redact_sensitive_text(val: str) -> str:
    """Mask email addresses and IP addresses as [redacted]."""
    val = _EMAIL_RE.sub("[redacted]", val)
    val = _IPV4_RE.sub("[redacted]", val)
    val = _IPV6_RE.sub("[redacted]", val)
    return val


def validate_and_clean_metadata(action: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Validate metadata against allowlist, check types, redact free-text, and enforce byte cap."""
    if metadata is None:
        metadata = {}

    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a dictionary")

    spec = ACTION_METADATA_SPECS.get(action)
    if spec is None:
        raise ValueError(f"Unknown audit action: {action}")

    # Check for unknown keys
    for k in metadata:
        if k not in spec:
            raise ValueError(f"Disallowed metadata key '{k}' for action '{action}'")

    cleaned: dict[str, Any] = {}
    for k, val in metadata.items():
        allowed_types, should_redact = spec[k]

        # Guard against bool being an instance of int in Python
        if int in allowed_types and bool not in allowed_types and isinstance(val, bool):
            raise ValueError(f"Metadata key '{k}' expected int but got bool")

        if not isinstance(val, allowed_types):
            type_names = ", ".join(t.__name__ for t in allowed_types)
            raise ValueError(
                f"Metadata key '{k}' has invalid type {type(val).__name__}, expected {type_names}"
            )

        if isinstance(val, uuid.UUID):
            val = str(val)

        if should_redact and isinstance(val, str):
            val = val[:500]
            val = redact_sensitive_text(val)

        cleaned[k] = val

    # Extra action-specific checks
    if action == "verification.lapsed":
        if "outcome" in cleaned and cleaned["outcome"] != "absent":
            raise ValueError("verification.lapsed outcome must be 'absent'")

    # Enforce 2048-byte cap
    serialized = json.dumps(cleaned)
    if len(serialized.encode("utf-8")) > 2048:
        raise ValueError("Metadata exceeds maximum allowed size of 2048 bytes")

    return cleaned


def record_event(
    session: Session,
    *,
    org_id: int,
    actor_type: str,
    action: str,
    target_type: str,
    target_id: str | int,
    actor_user_id: uuid.UUID | str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Record an audit event by adding it to the caller's session.

    Never commits or flushes so the event shares the caller's transaction.
    """
    if actor_type not in ALLOWED_ACTOR_TYPES:
        raise ValueError(
            f"Invalid actor_type: {actor_type}. Must be one of {sorted(ALLOWED_ACTOR_TYPES)}"
        )

    if action not in AUDIT_ACTIONS:
        raise ValueError(f"Invalid audit action: {action}")

    # Enforce target_type conventions
    if (
        action.startswith("domain.")
        or action.startswith("verification.")
        or action == "scan.queued"
    ):
        if target_type != "domain":
            raise ValueError(
                f"Action '{action}' requires target_type='domain', got '{target_type}'"
            )
    elif action in ("org.created", "org.deleted"):
        if target_type != "org":
            raise ValueError(f"Action '{action}' requires target_type='org', got '{target_type}'")
    elif action.startswith("account."):
        if target_type != "user":
            raise ValueError(
                f"Action '{action}' requires target_type='user', got '{target_type}'"
            )
    elif action.startswith("invite."):
        if target_type != "invite":
            raise ValueError(
                f"Action '{action}' requires target_type='invite', got '{target_type}'"
            )
    elif action.startswith("membership."):
        if target_type != "membership":
            raise ValueError(
                f"Action '{action}' requires target_type='membership', got '{target_type}'"
            )

    cleaned_metadata = validate_and_clean_metadata(action, metadata)

    parsed_user_id: uuid.UUID | None = None
    if actor_user_id is not None:
        if isinstance(actor_user_id, str):
            parsed_user_id = uuid.UUID(actor_user_id)
        elif isinstance(actor_user_id, uuid.UUID):
            parsed_user_id = actor_user_id
        else:
            raise ValueError(f"Invalid actor_user_id type: {type(actor_user_id)}")

    event = AuditEvent(
        org_id=org_id,
        actor_type=actor_type,
        actor_user_id=parsed_user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        metadata_=cleaned_metadata,
    )
    session.add(event)
    return event


def build_audit_query(
    org_id: int,
    domain_id: int | None = None,
    action: str | None = None,
    limit: int = 50,
    before_id: int | None = None,
    include_user: bool = False,
) -> Select:
    """Build shared audit events query used by both JSON API and UI fragments."""
    if include_user:
        stmt = select(AuditEvent, User.email).outerjoin(
            User, AuditEvent.actor_user_id == User.id
        )
    else:
        stmt = select(AuditEvent)

    stmt = stmt.where(AuditEvent.org_id == org_id)
    if domain_id is not None:
        stmt = stmt.where(
            AuditEvent.target_type == "domain", AuditEvent.target_id == str(domain_id)
        )
    if action is not None:
        stmt = stmt.where(AuditEvent.action == action)
    if before_id is not None:
        stmt = stmt.where(AuditEvent.id < before_id)
    stmt = stmt.order_by(AuditEvent.id.desc()).limit(limit)
    return stmt

