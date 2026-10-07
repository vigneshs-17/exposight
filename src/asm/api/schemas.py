"""Pydantic request and response schemas for the Exposight REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(..., description="Application health status (ok/error)")
    database: str = Field(..., description="Database connection status (connected/disconnected)")


class DomainCreate(BaseModel):
    """Request payload for creating a new monitored domain."""

    name: str = Field(..., description="Target domain name (e.g. example.com)")


class DomainVerificationRead(BaseModel):
    """Response schema for domain ownership verification status and instructions."""

    domain_id: int
    domain_name: str
    status: Literal["pending", "verified", "lapsed"]
    method: Literal["dns_txt", "operator"]
    token: str
    record_name: str
    record_type: str = "TXT"
    record_value: str
    verified_at: datetime | None = None
    last_checked_at: datetime | None = None
    consecutive_misses: int = 0
    verification_reason: str | None = None
    verification_expires_at: datetime | None = None
    is_verified: bool = False
    check_outcome: Literal["match", "absent", "unknown"] | None = None
    check_detail: str | None = None

    model_config = ConfigDict(from_attributes=True)


class DomainRead(BaseModel):
    """Response schema for a monitored domain record."""

    id: int
    org_id: int
    name: str
    verification_status: str
    verification_token: str
    verification_method: str
    verified_at: datetime | None = None
    last_checked_at: datetime | None = None
    consecutive_misses: int = 0
    verification_reason: str | None = None
    verification_expires_at: datetime | None = None
    scan_interval_hours: int | None = None
    next_scan_at: datetime | None = None
    alerts_enabled: bool = False
    alert_emails: list[str] = Field(default_factory=list)
    alert_min_severity: str = "MEDIUM"
    created_at: datetime
    verification_record_name: str
    verification_record_type: str = "TXT"
    verification_record_value: str
    is_verified: bool = False

    model_config = ConfigDict(from_attributes=True)


class DomainScheduleUpdate(BaseModel):
    """Request payload for updating a domain's scan schedule."""

    interval_hours: int | None = Field(
        default=None,
        ge=6,
        le=720,
        description="Scan interval in hours (6 to 720), or null to disable schedule.",
    )


class DomainAlertsUpdate(BaseModel):
    """Request payload for configuring domain email alerts."""

    alerts_enabled: bool
    alert_emails: list[EmailStr] = Field(default_factory=list)
    alert_min_severity: str = Field(
        default="MEDIUM",
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$",
        description="Minimum severity threshold to trigger alerts (CRITICAL..INFO)",
    )

    @field_validator("alert_emails")
    @classmethod
    def validate_no_crlf(cls, emails: list[EmailStr]) -> list[EmailStr]:
        for e in emails:
            if "\r" in e or "\n" in e:
                raise ValueError(
                    "Email addresses must not contain carriage return or newline characters"
                )
        return emails

    @model_validator(mode="after")
    def validate_email_count(self) -> DomainAlertsUpdate:
        if self.alerts_enabled:
            if len(self.alert_emails) < 1 or len(self.alert_emails) > 5:
                raise ValueError(
                    "When alerts are enabled, between 1 and 5 alert_emails must be provided"
                )
        else:
            if len(self.alert_emails) > 5:
                raise ValueError("No more than 5 alert_emails may be specified")
        return self


class AlertNotificationRead(BaseModel):
    """Response schema for an outbox alert notification."""

    id: int
    domain_id: int
    scan_run_id: int | None = None
    recipient: str
    subject: str
    body: str
    status: str
    attempts: int
    max_attempts: int
    next_attempt_at: datetime
    last_error: str | None = None
    sent_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanStageRead(BaseModel):
    """Response schema for a single pipeline stage execution status."""

    stage: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    error: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanRunRead(BaseModel):
    """Response schema for a scan run execution."""

    id: int
    domain_id: int
    status: str
    trigger: str = "manual"
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    attempts: int = 0
    max_attempts: int = 3
    change_detection: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanRunDetail(ScanRunRead):
    """Detailed response schema for a scan run including stage progress."""

    stages: list[ScanStageRead] = []

    model_config = ConfigDict(from_attributes=True)


class ScanChangeRead(BaseModel):
    """Response schema for an attack surface change record."""

    id: int
    domain_id: int
    scan_run_id: int
    baseline_scan_run_id: int
    change_type: str
    category: str
    severity: str
    asset: str
    detail: str
    evidence: str
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None
    observed_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ActiveScanConflict(BaseModel):
    """Error schema returned when a scan is already active for a target domain."""

    detail: str
    active_scan_id: int


class UserRead(BaseModel):
    """Response schema for an authenticated user."""

    id: UUID
    email: str
    created_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgCreate(BaseModel):
    """Request payload for creating a new organization."""

    name: str = Field(..., min_length=1, max_length=128, description="Organization name")


class OrgRead(BaseModel):
    """Response schema for an organization."""

    id: int
    name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgWithRoleRead(OrgRead):
    """Response schema for an organization including the caller's role."""

    role: str


class OrgMemberRead(BaseModel):
    """Response schema for an organization member."""

    user_id: UUID
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgInviteCreate(BaseModel):
    """Request payload for inviting someone to an organization by email."""

    email: EmailStr = Field(..., description="Email address the invite is issued to")
    role: Literal["owner", "admin", "viewer"] = Field(
        default="viewer",
        description="Role granted when the invite is accepted",
    )


class OrgInviteRead(BaseModel):
    """A pending invite (the token is never returned after creation)."""

    id: int
    email: str
    role: str
    created_at: datetime
    expires_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgInviteCreated(OrgInviteRead):
    """Response to invite creation: includes the one-time token, shown only once."""

    token: str = Field(..., description="One-time invite token; share it with the invitee")


class OrgInviteAccept(BaseModel):
    """Request payload for accepting an invite."""

    token: str = Field(..., min_length=20, max_length=128)


class OrgMemberUpdate(BaseModel):
    """Request payload for updating an organization member's role."""

    role: Literal["owner", "admin", "viewer"] = Field(
        ...,
        description="New role to assign to the member",
    )


class AuditEventRead(BaseModel):
    """Response schema for an audit event."""

    id: int
    org_id: int
    actor_type: str
    actor_user_id: UUID | None = None
    action: str
    target_type: str
    target_id: str
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metadata_", "metadata"),
    )
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

