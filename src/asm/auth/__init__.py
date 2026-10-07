"""Authentication and authorization package for Exposight."""

from asm.auth.config import AuthSettings, get_auth_settings
from asm.auth.jwks import JWKSManager, JWKSUnavailableError
from asm.auth.token import (
    AuthError,
    AuthServiceUnavailableError,
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
    extract_bearer_token,
    verify_access_token,
)
from asm.auth.upsert import upsert_user

__all__ = [
    "AuthError",
    "AuthServiceUnavailableError",
    "AuthSettings",
    "ExpiredTokenError",
    "InvalidTokenError",
    "JWKSManager",
    "JWKSUnavailableError",
    "MissingTokenError",
    "extract_bearer_token",
    "get_auth_settings",
    "upsert_user",
    "verify_access_token",
]
