"""Token decoding and cryptographic verification with PyJWT."""

import logging
import uuid
from typing import Any

import jwt
from jwt.exceptions import (
    ExpiredSignatureError as PyJWTExpiredSignatureError,
)
from jwt.exceptions import (
    InvalidTokenError as PyJWTInvalidTokenError,
)
from jwt.exceptions import (
    PyJWTError,
)

from asm.auth.config import AuthSettings
from asm.auth.jwks import JWKSManager, JWKSUnavailableError

logger = logging.getLogger(__name__)

ALLOWED_ALGORITHMS = ["ES256", "RS256"]


class AuthError(Exception):
    """Base exception for authentication errors."""

    pass


class MissingTokenError(AuthError):
    """Raised when Authorization header or token is missing."""

    pass


class InvalidTokenError(AuthError):
    """Raised when token signature, claims, or format are invalid.

    str(exc) may contain values copied from the attacker-controlled token
    header and is for logs only. public_message is a fixed string that is safe
    to return to clients (response body and WWW-Authenticate header).
    """

    def __init__(self, message: str, public_message: str | None = None) -> None:
        super().__init__(message)
        self.public_message = public_message or message


class ExpiredTokenError(AuthError):
    """Raised when token has expired beyond allowed leeway."""

    pass


class AuthServiceUnavailableError(AuthError):
    """Raised when JWKS service is unreachable."""

    pass


class AuthMisconfiguredError(AuthServiceUnavailableError):
    """Raised when authentication service is misconfigured (e.g. SUPABASE_URL not set)."""

    pass


def extract_bearer_token(authorization_header: str | None) -> str:
    """Extract bearer token from Authorization header without logging it."""
    if not authorization_header:
        raise MissingTokenError("Missing Authorization header")

    parts = authorization_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise InvalidTokenError("Authorization header must be Bearer token")

    token = parts[1].strip()
    if not token:
        raise MissingTokenError("Bearer token is empty")
    return token


def verify_access_token(
    token: str,
    settings: AuthSettings,
    jwks_manager: JWKSManager,
) -> dict[str, Any]:
    """Cryptographically verify Supabase JWT token against JWKS.

    Enforces:
    - SUPABASE_URL must be configured (fails closed with AuthMisconfiguredError).
    - Algorithm allowlist: ES256 and RS256 only (rejects HS256, none).
    - Signature verification against cached/refreshed JWKS key.
    - Issuer == {SUPABASE_URL}/auth/v1.
    - Audience == settings.jwt_audience (default 'authenticated').
    - Expiration (exp) with max 30s leeway.
    - Presence of 'sub' (valid UUID).
    - Rejection of anonymous tokens (is_anonymous == True).
    - Tokens are NEVER logged.
    """
    if not settings.is_configured:
        logger.error("Authentication rejected: SUPABASE_URL is not configured")
        raise AuthMisconfiguredError("Authentication not configured")

    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as exc:
        logger.warning("Failed to decode token header: %s", exc)
        raise InvalidTokenError("Malformed token header") from exc

    alg = unverified_header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        logger.warning("Rejected token with disallowed signing algorithm: %r", alg)
        raise InvalidTokenError(
            f"Unsupported signing algorithm: {alg}",
            public_message="Unsupported signing algorithm",
        )

    kid = unverified_header.get("kid")
    if not kid:
        logger.warning("Token header missing 'kid' claim")
        raise InvalidTokenError("Token header missing 'kid'")

    try:
        signing_key = jwks_manager.get_signing_key(kid)
    except JWKSUnavailableError as exc:
        raise AuthServiceUnavailableError(str(exc)) from exc

    if not signing_key:
        logger.warning("Unable to resolve signing key for kid %r", kid)
        raise InvalidTokenError(f"Unknown key ID '{kid}'", public_message="Unknown key ID")

    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=settings.jwt_audience,
            issuer=settings.expected_issuer,
            leeway=30,
            options={
                "require": ["sub", "exp", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except PyJWTExpiredSignatureError as exc:
        logger.warning("Token expired: %s", exc)
        raise ExpiredTokenError("Token has expired") from exc
    except (PyJWTInvalidTokenError, PyJWTError) as exc:
        logger.warning("Invalid token claims or signature: %s", exc)
        raise InvalidTokenError("Invalid token signature or claims") from exc
    except Exception as exc:
        logger.warning("Unexpected error decoding token: %s", exc)
        raise InvalidTokenError("Failed to decode token") from exc

    # Reject anonymous tokens
    if payload.get("is_anonymous") is True:
        logger.warning("Rejected token with is_anonymous=true")
        raise InvalidTokenError("Anonymous tokens are not allowed")

    sub_val = payload.get("sub")
    try:
        user_uuid = uuid.UUID(str(sub_val))
    except (ValueError, TypeError, AttributeError) as exc:
        logger.warning("Token 'sub' claim is not a valid UUID")
        raise InvalidTokenError("Token sub claim must be a valid UUID") from exc

    return {
        "user_id": user_uuid,
        "email": payload.get("email", ""),
        "claims": payload,
    }
