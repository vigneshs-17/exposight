"""REST API routes for ASM SaaS (multi-tenant scoped)."""

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from asm.api.deps import (
    DbSession,
    get_current_user,
    get_domain_for_org,
    get_scan_for_org,
    require_org_role,
)
from asm.api.schemas import (
    ActiveScanConflict,
    AlertNotificationRead,
    AuditEventRead,
    DomainAlertsUpdate,
    DomainCreate,
    DomainRead,
    DomainScheduleUpdate,
    DomainVerificationRead,
    HealthResponse,
    ScanChangeRead,
    ScanRunDetail,
    ScanRunRead,
)
from asm.audit import build_audit_query, recipients_changed, record_event
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
)
from asm.db.scans import enqueue_scan
from asm.validators import DomainValidationError, normalize_domain, validate_domain
from asm.verification import (
    VERIFICATION_CHECK_COOLDOWN_SECONDS,
    apply_check_outcome,
    check_dns_txt_verification,
    generate_verification_token,
    queue_domain_alert,
)

logger = logging.getLogger(__name__)

public_router = APIRouter()
router = APIRouter(prefix="/orgs/{org_id}", dependencies=[Depends(get_current_user)])


@public_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    responses={
        200: {"description": "Service is healthy and database is connected"},
        503: {"description": "Database connection failed"},
    },
)
def health_check(db: DbSession) -> HealthResponse:
    """Verify application health and database reachability."""
    try:
        db.execute(text("SELECT 1"))
        return HealthResponse(status="ok", database="connected")
    except Exception:
        logger.exception("Database health check ping failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "error", "database": "disconnected"},
        ) from None


@router.post(
    "/domains",
    response_model=DomainRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new domain for scanning within an organization",
    responses={
        201: {"description": "Domain registered successfully with verification instructions"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization not found (or non-member)"},
        409: {"description": "Domain already exists in this organization"},
        422: {"description": "Validation error"},
    },
)
def create_domain(
    org_id: int,
    payload: DomainCreate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Register a new domain within an organization in pending verification status."""
    try:
        validated_name = validate_domain(payload.name)
    except DomainValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid domain: {err}",
        ) from err

    normalized = normalize_domain(validated_name)

    existing = db.scalar(
        select(Domain).where(
            Domain.org_id == org_id,
            Domain.name == normalized,
        )
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{normalized}' already exists.",
        )

    token = generate_verification_token()
    domain = Domain(
        org_id=org_id,
        name=normalized,
        verification_status="pending",
        verification_token=token,
        verification_method="dns_txt",
    )
    db.add(domain)
    try:
        db.flush()
    except IntegrityError as err:
        # Two concurrent requests can both pass the existence check above; the
        # unique constraint decides, and the loser gets 409 instead of a 500.
        db.rollback()
        if "uq_domains_org_id_name" not in str(err.orig):
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{normalized}' already exists.",
        ) from None

    _, caller_membership = auth_context
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="domain.created",
        target_type="domain",
        target_id=str(domain.id),
        metadata={"name": domain.name},
    )

    db.commit()
    db.refresh(domain)
    logger.info(
        "Registered domain %s (id=%d) for org %d in pending verification status",
        normalized,
        domain.id,
        org_id,
    )
    return domain


@router.get(
    "/domains",
    response_model=list[DomainRead],
    summary="List all registered domains in an organization",
    responses={
        200: {"description": "List of organization domains returned"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_domains(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Sequence[Domain]:
    """Retrieve all monitored domains for this organization ordered by ID."""
    return db.scalars(
        select(Domain).where(Domain.org_id == org_id).order_by(Domain.id.asc())
    ).all()


@router.get(
    "/domains/{domain_id}",
    response_model=DomainRead,
    summary="Get domain details by ID within an organization",
    responses={
        200: {"description": "Domain details returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def get_domain(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Domain:
    """Retrieve details for a single domain by ID scoped to organization."""
    return get_domain_for_org(db, org_id, domain_id)


def _domain_to_verification_read(
    domain: Domain,
    check_outcome: Literal["match", "absent", "unknown"] | None = None,
    check_detail: str | None = None,
) -> DomainVerificationRead:
    return DomainVerificationRead(
        domain_id=domain.id,
        domain_name=domain.name,
        status=domain.verification_status,  # type: ignore[arg-type]
        method=domain.verification_method,  # type: ignore[arg-type]
        token=domain.verification_token,
        record_name=domain.verification_record_name,
        record_type="TXT",
        record_value=domain.verification_record_value,
        verified_at=domain.verified_at,
        last_checked_at=domain.last_checked_at,
        consecutive_misses=domain.consecutive_misses,
        verification_reason=domain.verification_reason,
        verification_expires_at=domain.verification_expires_at,
        is_verified=domain.is_verified,
        check_outcome=check_outcome,
        check_detail=check_detail,
    )


@router.get(
    "/domains/{domain_id}/verification",
    response_model=DomainVerificationRead,
    summary="Get domain ownership verification status and DNS TXT record details",
    responses={
        200: {"description": "Domain verification details and instructions returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def get_domain_verification(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> DomainVerificationRead:
    """Retrieve current verification status and the exact DNS TXT record to publish."""
    domain = get_domain_for_org(db, org_id, domain_id)
    return _domain_to_verification_read(domain)


@router.post(
    "/domains/{domain_id}/verification/check",
    response_model=DomainVerificationRead,
    summary="Trigger immediate DNS TXT check for domain ownership verification",
    responses={
        200: {"description": "Verification check completed; returns updated status"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain ID not found"},
        429: {"description": "Verification check is on cooldown"},
    },
)
def check_domain_verification(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> DomainVerificationRead:
    """Perform immediate DNS TXT record lookup under row lock with a 30s rate limit cooldown."""
    stmt = (
        select(Domain)
        .where(Domain.org_id == org_id, Domain.id == domain_id)
        .with_for_update()
    )
    domain = db.scalar(stmt)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain ID {domain_id} not found in organization {org_id}.",
        )

    now_utc = datetime.now(UTC)
    if domain.last_checked_at is not None:
        elapsed = (now_utc - domain.last_checked_at).total_seconds()
        if elapsed < VERIFICATION_CHECK_COOLDOWN_SECONDS:
            retry_after = max(1, int(VERIFICATION_CHECK_COOLDOWN_SECONDS - elapsed))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Verification check is on cooldown. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )

    domain.last_checked_at = now_utc

    outcome, detail = check_dns_txt_verification(domain.name, domain.verification_token)
    just_lapsed = apply_check_outcome(domain, outcome, now_utc)
    if just_lapsed:
        logger.warning(
            "Domain %s (id=%d) lapsed after 2 consecutive misses (%s)",
            domain.name,
            domain.id,
            detail,
        )
        queue_domain_alert(
            db,
            domain,
            subject="Domain verification lapsed: monitoring paused",
            body=(
                f"Domain verification for '{domain.name}' has lapsed after 2 "
                "consecutive failed DNS checks. Automated scheduled monitoring "
                "is paused until ownership is re-verified."
            ),
        )

    _, caller_membership = auth_context
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="verification.checked",
        target_type="domain",
        target_id=str(domain.id),
        metadata={
            "outcome": outcome.value,
            "consecutive_misses": domain.consecutive_misses,
        },
    )
    if just_lapsed:
        record_event(
            db,
            org_id=org_id,
            actor_type="system",
            action="verification.lapsed",
            target_type="domain",
            target_id=str(domain.id),
            metadata={
                "consecutive_misses": domain.consecutive_misses,
                "outcome": "absent",
            },
        )

    db.commit()
    db.refresh(domain)
    return _domain_to_verification_read(
        domain,
        check_outcome=outcome.value,  # type: ignore[arg-type]
        check_detail=detail,
    )


@router.post(
    "/domains/{domain_id}/verification/rotate",
    response_model=DomainVerificationRead,
    summary="Rotate verification token and reset status to pending",
    responses={
        200: {"description": "Token rotated successfully; status reset to pending"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def rotate_domain_verification(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> DomainVerificationRead:
    """Invalidate current verification token, generate a new token, and reset status to pending."""
    stmt = (
        select(Domain)
        .where(Domain.org_id == org_id, Domain.id == domain_id)
        .with_for_update()
    )
    domain = db.scalar(stmt)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain ID {domain_id} not found in organization {org_id}.",
        )

    domain.verification_token = generate_verification_token()
    domain.verification_status = "pending"
    domain.verification_method = "dns_txt"
    domain.verified_at = None
    domain.consecutive_misses = 0
    domain.verification_reason = None
    domain.verification_expires_at = None
    domain.next_reverification_at = None

    _, caller_membership = auth_context
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="verification.rotated",
        target_type="domain",
        target_id=str(domain.id),
        metadata={},
    )

    db.commit()
    db.refresh(domain)
    logger.info(
        "Rotated verification token for domain %s (id=%d); reset to pending",
        domain.name,
        domain.id,
    )
    return _domain_to_verification_read(domain)


@router.post(
    "/domains/{domain_id}/scans",
    response_model=ScanRunRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a multi-stage scan run for a domain",
    responses={
        200: {
            "description": "Idempotent request returning existing scan run",
            "model": ScanRunRead,
        },
        202: {"description": "Scan run queued successfully", "model": ScanRunRead},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain ID not found"},
        409: {"description": "Active scan already in progress", "model": ActiveScanConflict},
        422: {"description": "Domain is not verified for active scanning"},
    },
)
def queue_scan(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
    response: Response,
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", max_length=128)
    ] = None,
) -> Any:
    """Queue a scan run for a verified domain with atomic idempotency and concurrency guards."""
    domain = get_domain_for_org(db, org_id, domain_id)

    if domain.verification_status != "verified":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Domain '{domain.name}' is not verified for active scanning. "
                "Ownership verification is required."
            ),
        )

    if idempotency_key:
        existing_idempotent = db.scalar(
            select(ScanRun).where(
                ScanRun.domain_id == domain.id,
                ScanRun.idempotency_key == idempotency_key,
            )
        )
        if existing_idempotent:
            response.status_code = status.HTTP_200_OK
            return existing_idempotent

    try:
        scan_run = enqueue_scan(db, domain.id, trigger="manual", idempotency_key=idempotency_key)
        _, caller_membership = auth_context
        record_event(
            db,
            org_id=org_id,
            actor_type="user",
            actor_user_id=caller_membership.user_id,
            action="scan.queued",
            target_type="domain",
            target_id=str(domain.id),
            metadata={"scan_run_id": scan_run.id, "trigger": "manual"},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        if idempotency_key:
            existing_idempotent = db.scalar(
                select(ScanRun).where(
                    ScanRun.domain_id == domain.id,
                    ScanRun.idempotency_key == idempotency_key,
                )
            )
            if existing_idempotent:
                response.status_code = status.HTTP_200_OK
                return existing_idempotent

        active_id = db.scalar(
            select(ScanRun.id).where(
                ScanRun.domain_id == domain.id,
                ScanRun.status.in_(["queued", "running"]),
            )
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": "An active scan run is already in progress for this domain.",
                "active_scan_id": active_id or 0,
            },
        )

    db.refresh(scan_run)
    return scan_run


@router.get(
    "/domains/{domain_id}/scans",
    response_model=list[ScanRunRead],
    summary="List historical scan runs for a domain",
    responses={
        200: {"description": "List of scan runs returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def list_domain_scans(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[ScanRun]:
    """Retrieve historical scan runs for a domain with optional status filtering and pagination."""
    domain = get_domain_for_org(db, org_id, domain_id)

    query = select(ScanRun).where(ScanRun.domain_id == domain.id)
    if status_filter:
        query = query.where(ScanRun.status == status_filter)
    query = query.order_by(ScanRun.id.desc()).offset(offset).limit(min(limit, 100))
    return db.scalars(query).all()


@router.get(
    "/scans",
    response_model=list[ScanRunRead],
    summary="List all historical scan runs across all domains in an organization",
    responses={
        200: {"description": "List of organization scan runs returned"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_org_scans(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[ScanRun]:
    """Retrieve all historical scan runs across all domains in this organization."""
    query = (
        select(ScanRun)
        .join(Domain, ScanRun.domain_id == Domain.id)
        .where(Domain.org_id == org_id)
    )
    if status_filter:
        query = query.where(ScanRun.status == status_filter)
    query = query.order_by(ScanRun.id.desc()).offset(offset).limit(min(limit, 100))
    return db.scalars(query).all()


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRunDetail,
    summary="Get scan run details and stage progress",
    responses={
        200: {"description": "Scan run details returned"},
        404: {"description": "Organization or Scan run ID not found"},
    },
)
def get_scan(
    org_id: int,
    scan_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> ScanRun:
    """Retrieve execution status, retry count, and per-stage progress for a scan run."""
    return get_scan_for_org(db, org_id, scan_id)


@router.get(
    "/scans/{scan_id}/results/{stage}",
    summary="Get raw JSON artifact report for a specific pipeline stage",
    responses={
        200: {"description": "Stage artifact report returned"},
        404: {"description": "Organization, scan run, or stage result not found"},
    },
)
def get_scan_stage_result(
    org_id: int,
    scan_id: int,
    stage: str,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> dict[str, Any]:
    """Retrieve the JSONB artifact report produced by a specific pipeline stage."""
    scan = get_scan_for_org(db, org_id, scan_id)

    res = db.scalar(
        select(ScanResult).where(
            ScanResult.scan_run_id == scan.id,
            ScanResult.stage == stage,
        )
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No artifact report found for stage '{stage}' in scan run {scan_id}.",
        )
    return res.report


@router.get(
    "/scans/{scan_id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected in a scan run",
    responses={
        200: {"description": "List of scan changes returned"},
        404: {"description": "Organization or Scan run ID not found"},
    },
)
def get_scan_changes(
    org_id: int,
    scan_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Sequence[ScanChange]:
    """Retrieve attack surface changes detected specifically in a scan run."""
    scan = get_scan_for_org(db, org_id, scan_id)
    stmt = select(ScanChange).where(ScanChange.scan_run_id == scan.id).order_by(ScanChange.id.asc())
    return db.scalars(stmt).all()


@router.get(
    "/domains/{domain_id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected for a domain",
    responses={
        200: {"description": "List of detected changes returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def list_domain_changes(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    change_type: Annotated[str | None, Query(description="Filter by change_type")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    since: Annotated[
        str | None,
        Query(description="Filter changes observed on or after timestamp (ISO-8601)"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[ScanChange]:
    """Retrieve historical attack surface changes for a domain, newest first."""
    domain = get_domain_for_org(db, org_id, domain_id)

    stmt = select(ScanChange).where(ScanChange.domain_id == domain.id)
    if change_type:
        stmt = stmt.where(ScanChange.change_type == change_type)
    if severity:
        stmt = stmt.where(ScanChange.severity == severity)
    if category:
        stmt = stmt.where(ScanChange.category == category)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace(" ", "+"))
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid ISO-8601 datetime format for 'since': {since}",
            ) from err
        stmt = stmt.where(ScanChange.observed_at >= since_dt)

    stmt = (
        stmt.order_by(ScanChange.observed_at.desc(), ScanChange.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return db.scalars(stmt).all()


@router.put(
    "/domains/{domain_id}/schedule",
    response_model=DomainRead,
    summary="Configure recurring scan schedule for a domain",
    responses={
        200: {"description": "Schedule updated successfully"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain not found"},
        422: {"description": "Validation error or domain not authorized"},
    },
)
def update_domain_schedule(
    org_id: int,
    domain_id: int,
    payload: DomainScheduleUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Configure or disable automated periodic scanning for an authorized domain."""
    domain = get_domain_for_org(db, org_id, domain_id)

    old_interval = domain.scan_interval_hours
    if payload.interval_hours is None:
        domain.scan_interval_hours = None
        domain.next_scan_at = None
    else:
        if domain.verification_status != "verified":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Domain '{domain.name}' is not verified for scanning.",
            )

        if domain.scan_interval_hours is None:
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now()
        else:
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now() + text("interval '1 hour' * :h").bindparams(
                h=payload.interval_hours
            )

    _, caller_membership = auth_context
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="domain.schedule_changed",
        target_type="domain",
        target_id=str(domain.id),
        metadata={
            "old_interval_hours": old_interval,
            "new_interval_hours": payload.interval_hours,
        },
    )

    db.commit()
    db.refresh(domain)
    return domain


@router.put(
    "/domains/{domain_id}/alerts",
    response_model=DomainRead,
    summary="Configure attack surface change email alerts for a domain",
    responses={
        200: {"description": "Alert settings updated successfully"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain not found"},
        422: {"description": "Domain not verified or validation error"},
    },
)
def update_domain_alerts(
    org_id: int,
    domain_id: int,
    payload: DomainAlertsUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Configure or disable automated email alerts for detected attack surface exposures."""
    domain = get_domain_for_org(db, org_id, domain_id)

    if domain.verification_status != "verified" and payload.alerts_enabled:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Domain '{domain.name}' is not verified.",
        )

    old_enabled = domain.alerts_enabled
    old_severity = domain.alert_min_severity
    old_emails = list(domain.alert_emails or [])
    new_emails = [str(email) for email in payload.alert_emails]

    domain.alerts_enabled = payload.alerts_enabled
    domain.alert_emails = new_emails
    domain.alert_min_severity = payload.alert_min_severity

    _, caller_membership = auth_context
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="domain.alerts_changed",
        target_type="domain",
        target_id=str(domain.id),
        metadata={
            "old_enabled": old_enabled,
            "new_enabled": payload.alerts_enabled,
            "old_min_severity": old_severity,
            "new_min_severity": payload.alert_min_severity,
            # Counts and a changed flag only: recipient addresses never enter the audit log.
            "old_recipient_count": len(old_emails),
            "new_recipient_count": len(new_emails),
            "recipients_changed": recipients_changed(old_emails, new_emails),
        },
    )

    db.commit()
    db.refresh(domain)
    return domain


@router.get(
    "/domains/{domain_id}/alert-notifications",
    response_model=list[AlertNotificationRead],
    summary="List alert notifications for a domain",
    responses={
        200: {"description": "List of alert notifications returned"},
        404: {"description": "Organization or Domain not found"},
    },
)
def list_domain_alert_notifications(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> Sequence[AlertNotification]:
    """Retrieve historical alert notifications for a domain with optional status filtering."""
    domain = get_domain_for_org(db, org_id, domain_id)

    query = select(AlertNotification).where(AlertNotification.domain_id == domain.id)
    if status_filter:
        query = query.where(AlertNotification.status == status_filter)
    query = (
        query.order_by(AlertNotification.created_at.desc(), AlertNotification.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return db.scalars(query).all()


@router.get(
    "/audit-events",
    response_model=list[AuditEventRead],
    summary="List organization audit events",
    responses={
        200: {"description": "List of audit events returned"},
        403: {"description": "Insufficient permissions (admin or owner required)"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_audit_events(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
    domain_id: Annotated[int | None, Query(description="Filter by domain ID")] = None,
    action: Annotated[str | None, Query(description="Filter by action")] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Max items to return")] = 50,
    before_id: Annotated[
        int | None,
        Query(description="Keyset cursor: return events with id < before_id"),
    ] = None,
) -> list[AuditEventRead]:
    """Retrieve audit trail of events for this organization, newest first."""
    stmt = build_audit_query(
        org_id=org_id,
        domain_id=domain_id,
        action=action,
        limit=limit,
        before_id=before_id,
        include_user=False,
    )
    events = db.scalars(stmt).all()
    return [AuditEventRead.model_validate(e) for e in events]


