"""Organization and membership management routes."""

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, func, select, update

from asm.api.deps import CurrentUser, DbSession, require_org_role
from asm.api.schemas import (
    OrgCreate,
    OrgInviteAccept,
    OrgInviteCreate,
    OrgInviteCreated,
    OrgInviteRead,
    OrgMemberRead,
    OrgMemberUpdate,
    OrgRead,
    OrgWithRoleRead,
)
from asm.audit import record_event
from asm.db.models import Domain, Membership, Organization, OrgInvite, ScanRun, User
from asm.ratelimit import MAX_OWNED_ORGS_PER_USER, quota_exceeded

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs", tags=["Organizations"])

INVITE_TTL = timedelta(days=7)


@router.post(
    "",
    response_model=OrgRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new organization",
    responses={
        201: {"description": "Organization created successfully"},
        401: {"description": "Authentication required"},
    },
)
def create_organization(
    payload: OrgCreate,
    current_user: CurrentUser,
    db: DbSession,
) -> OrgRead:
    """Create a new organization and assign creator as owner."""
    # Lock the user row so concurrent creates cannot both pass the quota count.
    db.execute(select(User.id).where(User.id == current_user.id).with_for_update())
    owned = db.scalar(
        select(func.count(Membership.id)).where(
            Membership.user_id == current_user.id, Membership.role == "owner"
        )
    )
    if (owned or 0) >= MAX_OWNED_ORGS_PER_USER:
        raise quota_exceeded(
            f"Organization quota reached: you can own at most {MAX_OWNED_ORGS_PER_USER}."
        )

    org = Organization(name=payload.name)
    db.add(org)
    db.flush()  # populate org.id

    membership = Membership(
        org_id=org.id,
        user_id=current_user.id,
        role="owner",
    )
    db.add(membership)

    record_event(
        db,
        org_id=org.id,
        actor_type="user",
        actor_user_id=current_user.id,
        action="org.created",
        target_type="org",
        target_id=str(org.id),
        metadata={"name": org.name},
    )

    db.commit()
    db.refresh(org)

    logger.info("User %s created organization %d (%s)", current_user.id, org.id, org.name)
    return OrgRead.model_validate(org)


@router.get(
    "",
    response_model=list[OrgWithRoleRead],
    summary="List organizations current user belongs to",
    responses={
        200: {"description": "List of user organizations with roles"},
        401: {"description": "Authentication required"},
    },
)
def list_my_organizations(
    current_user: CurrentUser,
    db: DbSession,
) -> list[OrgWithRoleRead]:
    """Retrieve all organizations where current user has an active membership."""
    query = (
        select(Organization.id, Organization.name, Organization.created_at, Membership.role)
        .join(Membership, Organization.id == Membership.org_id)
        .where(Membership.user_id == current_user.id)
        .order_by(Organization.id.asc())
    )
    results = db.execute(query).all()
    return [
        OrgWithRoleRead(
            id=row.id,
            name=row.name,
            role=row.role,
            created_at=row.created_at,
        )
        for row in results
    ]


TOMBSTONE_KIND = "deleted"


@router.delete(
    "/{org_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an organization and all of its domains and scan data",
    responses={
        204: {"description": "Organization deleted"},
        401: {"description": "Authentication required"},
        403: {"description": "Only owners can delete an organization"},
        404: {"description": "Organization not found (or non-member)"},
        409: {"description": "A scan in this organization is running"},
    },
)
def delete_organization(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("owner"))],
    db: DbSession,
) -> Response:
    """Delete the org's domains (cascading to scans, changes and alert notifications),
    memberships and invites.

    The organization row itself stays as a tombstone named deleted-org-<id>: audit
    events reference it (ON DELETE RESTRICT) and the audit log is append-only. With
    no memberships left, nobody can reach it again.

    Refused with 409 while a scan is running (as asm admin move-domain). Queued scans
    and schedules are cancelled in the same transaction as the delete.
    """
    _, caller_membership = auth_context
    org = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())

    # Lock the org's active scans: the worker claims with SKIP LOCKED, so a queued scan
    # cannot start running between this check and the delete.
    active = db.execute(
        select(ScanRun.id, ScanRun.status)
        .join(Domain, Domain.id == ScanRun.domain_id)
        .where(Domain.org_id == org_id, ScanRun.status.in_(("queued", "running")))
        .with_for_update(of=ScanRun)
    ).all()
    running_ids = sorted(row.id for row in active if row.status == "running")
    if running_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A scan is running in this organization (scan_run_id={running_ids[0]}). "
            "Wait for it to finish, then retry.",
        )
    queued_ids = [row.id for row in active]
    queued_cancelled = 0
    if queued_ids:
        queued_cancelled = db.execute(
            update(ScanRun)
            .where(ScanRun.id.in_(queued_ids))
            .values(
                status="cancelled",
                finished_at=func.now(),
                error="The organization was deleted.",
            )
        ).rowcount
    schedules_cancelled = db.execute(
        update(Domain)
        .where(Domain.org_id == org_id, Domain.scan_interval_hours.is_not(None))
        .values(scan_interval_hours=None, next_scan_at=None)
    ).rowcount

    domains_deleted = db.execute(delete(Domain).where(Domain.org_id == org_id)).rowcount
    invites_deleted = db.execute(delete(OrgInvite).where(OrgInvite.org_id == org_id)).rowcount
    members_removed = db.execute(delete(Membership).where(Membership.org_id == org_id)).rowcount
    org.name = f"deleted-org-{org_id}"
    org.system_kind = TOMBSTONE_KIND

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="org.deleted",
        target_type="org",
        target_id=str(org_id),
        metadata={
            "domains_deleted": domains_deleted,
            "members_removed": members_removed,
            "invites_deleted": invites_deleted,
            "schedules_cancelled": schedules_cancelled,
            "queued_scans_cancelled": queued_cancelled,
        },
    )
    db.commit()
    logger.info(
        "User %s deleted org %d (%d domains)", caller_membership.user_id, org_id, domains_deleted
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{org_id}/members",
    response_model=list[OrgMemberRead],
    summary="List organization members",
    responses={
        200: {"description": "List of organization members"},
        401: {"description": "Authentication required"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_organization_members(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> list[OrgMemberRead]:
    """List members of an organization. Accessible to any member (viewer, admin, owner)."""
    query = (
        select(Membership.user_id, User.email, Membership.role, Membership.created_at)
        .join(User, Membership.user_id == User.id)
        .where(Membership.org_id == org_id)
        .order_by(Membership.created_at.asc())
    )
    rows = db.execute(query).all()
    return [
        OrgMemberRead(
            user_id=row.user_id,
            email=row.email,
            role=row.role,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/{org_id}/members",
    status_code=status.HTTP_410_GONE,
    summary="Removed: add members with an invite instead",
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found (or non-member)"},
        410: {"description": "Use POST /orgs/{org_id}/invites"},
    },
)
def add_organization_member(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
) -> Response:
    """Removed in v3.6b: adding members by email revealed which emails had accounts and
    added people without their consent. Membership checks still run first, so
    non-members keep getting 404 and viewers 403.
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Adding members directly was removed. Create an invite: POST /orgs/{org_id}/invites",
    )


def hash_invite_token(token: str) -> str:
    """Return the SHA-256 hex digest stored for an invite token (the token is never stored)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post(
    "/{org_id}/invites",
    response_model=OrgInviteCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Invite someone to the organization by email",
    responses={
        201: {"description": "Invite created; the token is shown only in this response"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def create_invite(
    org_id: int,
    payload: OrgInviteCreate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> OrgInviteCreated:
    """Create a single-use invite. The response is the same whether or not the email
    belongs to an existing account: users are never looked up by email.
    """
    _, caller_membership = auth_context
    if caller_membership.role != "owner" and payload.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can invite other owners",
        )

    token = secrets.token_urlsafe(32)
    invite = OrgInvite(
        org_id=org_id,
        email=str(payload.email).strip().lower(),
        role=payload.role,
        token_hash=hash_invite_token(token),
        invited_by_user_id=caller_membership.user_id,
        expires_at=datetime.now(UTC) + INVITE_TTL,
    )
    db.add(invite)
    db.flush()

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="invite.created",
        target_type="invite",
        target_id=str(invite.id),
        metadata={"role": invite.role, "expires_at": invite.expires_at.isoformat()},
    )
    db.commit()
    db.refresh(invite)
    logger.info("Created invite %d for org %d with role %s", invite.id, org_id, invite.role)
    return OrgInviteCreated(
        id=invite.id,
        email=invite.email,
        role=invite.role,
        created_at=invite.created_at,
        expires_at=invite.expires_at,
        token=token,
    )


@router.get(
    "/{org_id}/invites",
    response_model=list[OrgInviteRead],
    summary="List pending invites",
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_invites(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> list[OrgInviteRead]:
    """List invites that can still be accepted. Tokens are never returned."""
    invites = db.scalars(
        select(OrgInvite)
        .where(
            OrgInvite.org_id == org_id,
            OrgInvite.accepted_at.is_(None),
            OrgInvite.revoked_at.is_(None),
            OrgInvite.expires_at > func.now(),
        )
        .order_by(OrgInvite.id.desc())
    ).all()
    return [OrgInviteRead.model_validate(i) for i in invites]


@router.delete(
    "/{org_id}/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a pending invite",
    responses={
        204: {"description": "Invite revoked"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization or invite not found"},
        409: {"description": "Invite was already accepted or revoked"},
    },
)
def revoke_invite(
    org_id: int,
    invite_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Response:
    """Revoke an invite so its token can no longer be used."""
    _, caller_membership = auth_context
    invite = db.scalar(
        select(OrgInvite)
        .where(OrgInvite.id == invite_id, OrgInvite.org_id == org_id)
        .with_for_update()
    )
    if invite is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
    if invite.accepted_at is not None or invite.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Invite is no longer pending"
        )

    invite.revoked_at = datetime.now(UTC)
    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="invite.revoked",
        target_type="invite",
        target_id=str(invite.id),
        metadata={"role": invite.role},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


invites_router = APIRouter(prefix="/invites", tags=["Organizations"])

INVALID_INVITE_DETAIL = "Invite not found or no longer valid"


@invites_router.post(
    "/accept",
    response_model=OrgWithRoleRead,
    summary="Accept an organization invite",
    responses={
        200: {"description": "Joined the organization"},
        401: {"description": "Authentication required"},
        403: {"description": "Invite was issued to a different email address"},
        404: {"description": "Invite not found, expired, revoked or already used"},
        409: {"description": "Already a member of this organization"},
    },
)
def accept_invite(
    payload: OrgInviteAccept,
    current_user: CurrentUser,
    db: DbSession,
) -> OrgWithRoleRead:
    """Join an organization with a single-use invite token.

    The signed-in user's email (from the verified Supabase JWT) must equal the
    invite email. Supabase must have "Confirm email" enabled so that email is
    proven (see docs/DEPLOY.md). The invite row is locked so a token can only
    be used once, even by concurrent requests.
    """
    invite = db.scalar(
        select(OrgInvite)
        .where(OrgInvite.token_hash == hash_invite_token(payload.token))
        .with_for_update()
    )
    now = datetime.now(UTC)
    if (
        invite is None
        or invite.accepted_at is not None
        or invite.revoked_at is not None
        or invite.expires_at <= now
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=INVALID_INVITE_DETAIL)

    user_email = (current_user.email or "").strip().lower()
    if not user_email or user_email != invite.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This invite was issued to a different email address",
        )

    already = db.scalar(
        select(Membership.id).where(
            Membership.org_id == invite.org_id, Membership.user_id == current_user.id
        )
    )
    if already is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already a member of this organization",
        )

    membership = Membership(org_id=invite.org_id, user_id=current_user.id, role=invite.role)
    db.add(membership)
    invite.accepted_at = now
    invite.accepted_by_user_id = current_user.id
    db.flush()

    record_event(
        db,
        org_id=invite.org_id,
        actor_type="user",
        actor_user_id=current_user.id,
        action="membership.added",
        target_type="membership",
        target_id=str(membership.id),
        metadata={
            "user_id": str(current_user.id),
            "role": membership.role,
            "via": "invite",
            "invite_id": invite.id,
        },
    )
    db.commit()

    org = db.get(Organization, invite.org_id)
    logger.info("User %s joined org %d via invite %d", current_user.id, org.id, invite.id)
    return OrgWithRoleRead(
        id=org.id, name=org.name, role=membership.role, created_at=org.created_at
    )


@router.patch(
    "/{org_id}/members/{user_id}",
    response_model=OrgMemberRead,
    summary="Update organization member role",
    responses={
        200: {"description": "Member role updated"},
        401: {"description": "Authentication required"},
        403: {"description": "Only owners can update member roles"},
        404: {"description": "Organization not found (or non-member), or member not found"},
        422: {"description": "Cannot demote the last owner"},
    },
)
def update_member_role(
    org_id: int,
    user_id: uuid.UUID,
    payload: OrgMemberUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("owner"))],
    db: DbSession,
) -> OrgMemberRead:
    """Update a member's role. Restricted to owners. Enforces last-owner invariant."""
    _, caller_membership = auth_context

    target_member = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
        )
    ).scalar_one_or_none()
    if target_member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in organization",
        )

    if target_member.role == "owner" and payload.role != "owner":
        # Lock organization row to prevent concurrent last-owner race
        lock_stmt = select(Organization).where(Organization.id == org_id).with_for_update()
        db.execute(lock_stmt).scalar_one()

        remaining_owners = db.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == org_id,
                Membership.role == "owner",
                Membership.user_id != user_id,
            )
        )
        if (remaining_owners or 0) == 0:
            raise HTTPException(
                status_code=422,
                detail="Cannot demote the last owner of an organization",
            )

    old_role = target_member.role
    target_member.role = payload.role

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="membership.role_changed",
        target_type="membership",
        target_id=str(target_member.id),
        metadata={
            "user_id": str(user_id),
            "old_role": old_role,
            "new_role": payload.role,
        },
    )

    db.commit()
    db.refresh(target_member)

    target_user = db.get(User, user_id)
    return OrgMemberRead(
        user_id=target_member.user_id,
        email=target_user.email if target_user else "",
        role=target_member.role,
        created_at=target_member.created_at,
    )


@router.delete(
    "/{org_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from organization",
    responses={
        204: {"description": "Member removed"},
        401: {"description": "Authentication required"},
        403: {"description": "Only owners can remove other members"},
        404: {"description": "Organization not found (or non-member), or member not found"},
        422: {"description": "Cannot remove the last owner"},
    },
)
def remove_organization_member(
    org_id: int,
    user_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
) -> Response:
    """Remove a member from organization.

    - Any member may remove themselves (self-removal).
    - Removing other members requires owner role.
    - Last-owner invariant is strictly enforced.
    """
    caller_membership = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if caller_membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # If removing someone else, caller must be owner
    if current_user.id != user_id and caller_membership.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can remove other members",
        )

    target_member = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
        )
    ).scalar_one_or_none()
    if target_member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in organization",
        )

    if target_member.role == "owner":
        # Lock organization row to prevent concurrent last-owner race
        lock_stmt = select(Organization).where(Organization.id == org_id).with_for_update()
        db.execute(lock_stmt).scalar_one()

        remaining_owners = db.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == org_id,
                Membership.role == "owner",
                Membership.user_id != user_id,
            )
        )
        if (remaining_owners or 0) == 0:
            raise HTTPException(
                status_code=422,
                detail="Cannot remove the last owner of an organization",
            )

    target_member_id = target_member.id
    target_member_role = target_member.role

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=current_user.id,
        action="membership.removed",
        target_type="membership",
        target_id=str(target_member_id),
        metadata={"user_id": str(user_id), "role": target_member_role},
    )

    db.delete(target_member)
    db.commit()
    logger.info("Removed user %s from org %d", user_id, org_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


me_router = APIRouter(prefix="/me", tags=["Account"])


@me_router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete your own account",
    responses={
        204: {"description": "Account deleted"},
        401: {"description": "Authentication required"},
        403: {"description": "Account suspended"},
        409: {"description": "You are the only owner of one or more organizations"},
    },
)
def delete_my_account(current_user: CurrentUser, db: DbSession) -> Response:
    """Delete the signed-in user's account, memberships and invites sent to their email.

    Refused with 409 while the user is the only owner of any organization: they must
    hand ownership to someone else or delete those organizations first (D6). Suspended
    accounts get 403 from CurrentUser, so deleting cannot be used to shed a suspension.
    The sign-in provider's identity is not deleted (Exposight holds no admin key for it):
    signing in again creates a new, empty Exposight account.
    """
    user = db.scalar(select(User).where(User.id == current_user.id).with_for_update())
    memberships = db.scalars(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.org_id)
    ).all()

    owned_org_ids = [m.org_id for m in memberships if m.role == "owner"]
    # Lock the owned orgs so a concurrent demotion of the other owner cannot slip past.
    db.execute(
        select(Organization.id).where(Organization.id.in_(owned_org_ids)).with_for_update()
    )
    sole_owner_orgs = db.execute(
        select(Organization.id, Organization.name)
        .where(Organization.id.in_(owned_org_ids))
        .where(
            ~select(Membership.id)
            .where(
                Membership.org_id == Organization.id,
                Membership.role == "owner",
                Membership.user_id != user.id,
            )
            .exists()
        )
        .order_by(Organization.id)
    ).all()
    if sole_owner_orgs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "You are the only owner of these organizations. Transfer "
                "ownership or delete them first.",
                "organizations": [{"id": o.id, "name": o.name} for o in sole_owner_orgs],
            },
        )

    for m in memberships:
        record_event(
            db,
            org_id=m.org_id,
            actor_type="user",
            actor_user_id=user.id,
            action="account.deleted",
            target_type="user",
            target_id=str(user.id),
            metadata={"user_id": str(user.id), "role": m.role},
        )
    email = (user.email or "").strip().lower()
    if email:
        db.execute(delete(OrgInvite).where(func.lower(OrgInvite.email) == email))
    # Memberships go with the user row (ON DELETE CASCADE).
    db.execute(delete(User).where(User.id == user.id))
    db.commit()
    logger.info("User %s deleted their account (%d memberships)", user.id, len(memberships))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
