"""FastAPI authentication and authorization dependencies."""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.auth.config import AuthSettings, get_auth_settings
from asm.auth.jwks import JWKSManager
from asm.auth.token import (
    AuthMisconfiguredError,
    AuthServiceUnavailableError,
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
    extract_bearer_token,
    verify_access_token,
)
from asm.auth.upsert import upsert_user
from asm.db.models import Domain, Membership, Organization, ScanRun, User
from asm.db.session import get_db
from asm.ratelimit import (
    API_REQUESTS_PER_MINUTE_PER_USER,
    UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP,
    enforce_rate_limit,
)

DbSession = Annotated[Session, Depends(get_db)]

ROLE_RANKS: dict[str, int] = {
    "viewer": 1,
    "admin": 2,
    "owner": 3,
}

_auth_settings: AuthSettings | None = None
_jwks_manager: JWKSManager | None = None


def reset_auth_dependencies() -> None:
    """Reset cached auth settings and JWKS manager (for testing configuration changes)."""
    global _auth_settings, _jwks_manager
    _auth_settings = None
    _jwks_manager = None


def get_current_auth_settings() -> AuthSettings:
    """Retrieve or initialize global auth settings."""
    global _auth_settings
    if _auth_settings is None:
        _auth_settings = get_auth_settings()
    return _auth_settings


def get_current_jwks_manager() -> JWKSManager:
    """Retrieve or initialize global JWKS manager."""
    global _jwks_manager
    if _jwks_manager is None:
        settings = get_current_auth_settings()
        _jwks_manager = JWKSManager(
            jwks_url=settings.jwks_url,
            fetch_timeout=settings.jwks_fetch_timeout,
            min_refresh_interval=settings.jwks_min_refresh_interval,
            cache_ttl=settings.jwks_cache_ttl,
        )
    return _jwks_manager


def client_ip(request: Request) -> str:
    """Return the client IP for rate limiting.

    In production uvicorn runs with --proxy-headers and trusts X-Forwarded-For
    only from the Caddy subnet (--forwarded-allow-ips), so a client cannot
    choose this value by sending its own header.
    """
    return request.client.host if request.client else "unknown"


def get_current_user(
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
    settings: Annotated[AuthSettings, Depends(get_current_auth_settings)] = None,  # type: ignore[assignment]
    jwks_manager: Annotated[JWKSManager, Depends(get_current_jwks_manager)] = None,  # type: ignore[assignment]
) -> User:
    """Authenticate the request and apply the request rate limits.

    A failed authentication counts against the client IP's unauthenticated
    limit (so invalid tokens cannot be sprayed without limit); a successful
    one counts against the user's per-minute limit.

    Raises:
        HTTPException(401): Missing, malformed, invalid, or expired token.
        HTTPException(429): Rate limit used up (Retry-After header set).
        HTTPException(503): Misconfigured auth or upstream JWKS endpoint unreachable.
    """
    try:
        user = _authenticate(db, authorization, settings, jwks_manager)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            enforce_rate_limit(
                f"ip:{client_ip(request)}", UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP
            )
        raise
    enforce_rate_limit(f"user:{user.id}", API_REQUESTS_PER_MINUTE_PER_USER)
    return user


def _authenticate(
    db: Session,
    authorization: str | None,
    settings: AuthSettings,
    jwks_manager: JWKSManager,
) -> User:
    """Verify Supabase JWT token and just-in-time upsert user."""
    if not settings.is_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication not configured",
        )

    try:
        token = extract_bearer_token(authorization)
    except MissingTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must be Bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from None

    try:
        token_info = verify_access_token(
            token=token,
            settings=settings,
            jwks_manager=jwks_manager,
        )
    except ExpiredTokenError:

        auth_header = (
            'Bearer error="invalid_token", '
            'error_description="The token has expired"'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": auth_header},
        ) from None
    except InvalidTokenError as exc:
        # public_message is a fixed string; never echo token header values (alg, kid).
        auth_header = f'Bearer error="invalid_token", error_description="{exc.public_message}"'
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.public_message,
            headers={"WWW-Authenticate": auth_header},
        ) from None
    except AuthMisconfiguredError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication not configured",
        ) from None
    except AuthServiceUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        ) from exc

    user = upsert_user(session=db, user_id=token_info["user_id"], email=token_info["email"])
    db.commit()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_org_role(minimum_role: str):
    """Dependency factory enforcing membership and minimum role in an organization.

    CRITICAL SECURITY INVARIANT:
    A non-member attempting to access an organization's resources always receives
    HTTP 404 (Not Found), NEVER HTTP 403 (Forbidden), to prevent organization ID
    enumeration across multi-tenant boundaries.
    """
    if minimum_role not in ROLE_RANKS:
        raise ValueError(f"Unknown minimum role: {minimum_role}")

    def dependency(
        org_id: int,
        current_user: CurrentUser,
        db: DbSession,
    ) -> tuple[Organization, Membership]:
        membership = db.execute(
            select(Membership).where(
                Membership.org_id == org_id,
                Membership.user_id == current_user.id,
            )
        ).scalar_one_or_none()

        if membership is None:
            # Anti-enumeration rule: non-members receive 404, never 403
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        org = db.get(Organization, org_id)
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        if ROLE_RANKS[membership.role] < ROLE_RANKS[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient organization permissions",
            )

        return org, membership

    return dependency


def get_domain_for_org(db: Session, org_id: int, domain_id: int) -> Domain:
    """Retrieve domain by ID scoped to organization.

    CRITICAL SECURITY CHOKE POINT:
    Filters strictly by (Domain.id == domain_id AND Domain.org_id == org_id)
    directly in the SQL query. Returns HTTP 404 if the domain does not exist
    OR belongs to another organization, preventing cross-tenant existence disclosure.
    """
    stmt = select(Domain).where(
        Domain.id == domain_id,
        Domain.org_id == org_id,
    )
    domain = db.execute(stmt).scalar_one_or_none()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {domain_id} not found.",
        )
    return domain


def get_scan_for_org(db: Session, org_id: int, scan_id: int) -> ScanRun:
    """Retrieve scan run by ID scoped to organization via domain join.

    CRITICAL SECURITY CHOKE POINT:
    Filters strictly by (ScanRun.id == scan_id AND Domain.org_id == org_id)
    directly in SQL via a JOIN to Domain. Returns HTTP 404 if the scan does not exist
    OR belongs to a domain in another organization, preventing cross-tenant existence disclosure.
    """
    stmt = (
        select(ScanRun)
        .join(Domain, ScanRun.domain_id == Domain.id)
        .where(
            ScanRun.id == scan_id,
            Domain.org_id == org_id,
        )
    )
    scan_run = db.execute(stmt).scalar_one_or_none()
    if scan_run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run with ID {scan_id} not found.",
        )
    return scan_run
