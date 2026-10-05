"""Application configuration loaded from environment variables."""

import os
import sys
from functools import lru_cache
from urllib.parse import urlparse

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

VALID_ENVIRONMENTS = ("development", "test", "production")
LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "::1"}
PLACEHOLDER_MARKERS = ("change_me", "change-me", "your-production-project", "your-project")


def get_environment() -> str:
    """Return the ENVIRONMENT mode (development, test or production).

    Defaults to development. An unknown value fails startup instead of being
    silently treated as development, so a typo can never disable the guard.
    """
    value = os.getenv("ENVIRONMENT", "").strip().lower() or "development"
    if value not in VALID_ENVIRONMENTS:
        raise RuntimeError(
            f"ENVIRONMENT must be one of {', '.join(VALID_ENVIRONMENTS)}; got {value!r}"
        )
    return value


def is_production() -> bool:
    """Return True when ENVIRONMENT=production."""
    return get_environment() == "production"


def _looks_like_placeholder(value: str) -> bool:
    """Return True if a config value still holds an example placeholder."""
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def find_production_config_problems(
    database_url: str,
    supabase_url: str | None = None,
    supabase_publishable_key: str | None = None,
) -> list[str]:
    """List reasons this configuration is unsafe for production.

    Messages name the setting, never its value, so secrets are never logged.
    Pass supabase_url=None to skip auth checks (the worker does not use auth).
    """
    problems: list[str] = []

    try:
        url = make_url(database_url)
    except ArgumentError:
        problems.append("DATABASE_URL is not a valid database URL")
    else:
        if (url.database or "").endswith("_test"):
            problems.append("DATABASE_URL points to a test database (name ends with _test)")
        if (url.host or "").lower() in LOCAL_DB_HOSTS:
            problems.append("DATABASE_URL points to localhost (development database)")
        if _looks_like_placeholder(database_url):
            problems.append("DATABASE_URL still contains an example placeholder")
        if (url.username or "").lower() == "postgres":
            problems.append(
                "DATABASE_URL connects as the postgres superuser; use the app role (APP_DB_USER)"
            )

    if supabase_url is not None:
        parsed = urlparse(supabase_url.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            problems.append("SUPABASE_URL must be an https:// URL")
        elif _looks_like_placeholder(supabase_url):
            problems.append("SUPABASE_URL still contains an example placeholder")

        key = (supabase_publishable_key or "").strip()
        if not key or _looks_like_placeholder(key):
            problems.append("SUPABASE_PUBLISHABLE_KEY is empty or an example placeholder")

    return problems


def enforce_production_config(check_auth: bool) -> None:
    """Refuse to start in production with a development, test or placeholder config.

    Does nothing outside production. check_auth=False skips the Supabase
    checks for processes that do not authenticate users (the worker).
    """
    if not is_production():
        return
    supabase_url = None
    publishable_key = None
    if check_auth:
        supabase_url = os.getenv("SUPABASE_URL", "")
        publishable_key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    problems = find_production_config_problems(
        get_settings().database_url, supabase_url, publishable_key
    )
    if problems:
        raise RuntimeError(
            "Refusing to start with ENVIRONMENT=production: " + "; ".join(problems)
        )


class Settings(BaseSettings):
    """Runtime configuration for ASM SaaS services."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # DATABASE_URL is required with NO default. Fails startup if missing.
    database_url: str = Field(
        ...,
        description=(
            "PostgreSQL connection string "
            "(e.g. postgresql+psycopg://user:pass@host:5432/dbname)"
        ),
    )
    test_database_url: str | None = Field(
        default=None,
        description="Optional PostgreSQL connection string for test suite (must end in _test)",
    )
    supabase_publishable_key: str = Field(
        default="",
        description="Public non-secret Supabase publishable key for browser client authentication",
    )

    @field_validator("supabase_publishable_key")
    @classmethod
    def validate_publishable_key(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned.startswith("sb_secret_"):
            raise ValueError(
                "CRITICAL SECURITY MISCONFIGURATION: SUPABASE_PUBLISHABLE_KEY "
                "contains a secret service key ('sb_secret_...'). "
                "Only the public publishable/anon key may be configured."
            )
        return cleaned


@lru_cache
def get_settings() -> Settings:
    """Retrieve validated application settings or exit with a clear message."""
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as err:
        for error in err.errors():
            if error.get("loc") and error["loc"][0] == "supabase_publishable_key":
                msg = error.get("msg", "Invalid SUPABASE_PUBLISHABLE_KEY")
                raise RuntimeError(
                    f"CRITICAL SECURITY MISCONFIGURATION: {msg}"
                ) from err
        missing_fields = [
            error["loc"][0]
            for error in err.errors()
            if error["type"] == "missing"
        ]
        if "database_url" in missing_fields:
            sys.stderr.write(
                "Configuration Error: DATABASE_URL environment variable is required but not set.\n"
                "Please configure DATABASE_URL in your environment or .env file.\n"
            )
            raise RuntimeError(
                "DATABASE_URL environment variable is required but not set."
            ) from err
        raise
