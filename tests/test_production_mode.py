"""Tests for v3.6b production mode: startup guard, hidden API docs, JSON API headers, CSP origin."""

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from asm.api.main import app
from asm.api.routes_ui import build_csp_header, supabase_csp_origin
from asm.config import (
    enforce_production_config,
    find_production_config_problems,
    get_environment,
    get_settings,
)

GOOD_DB = "postgresql+psycopg://exposight_app:s3cretValue@db:5432/exposight"
GOOD_SUPABASE = "https://abcd1234.supabase.co"
GOOD_KEY = "sb_publishable_realLookingKey"


@pytest.fixture
def production_env(monkeypatch):
    """Run one test with ENVIRONMENT=production and a fresh settings cache."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", GOOD_DB)
    monkeypatch.setenv("SUPABASE_URL", GOOD_SUPABASE)
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", GOOD_KEY)
    get_settings.cache_clear()
    yield monkeypatch
    get_settings.cache_clear()


def test_clean_production_config_has_no_problems():
    assert find_production_config_problems(GOOD_DB, GOOD_SUPABASE, GOOD_KEY) == []


@pytest.mark.parametrize(
    ("database_url", "expected"),
    [
        ("postgresql+psycopg://u:p@db:5432/asm_test", "test database"),
        ("postgresql+psycopg://u:p@localhost:5432/exposight", "localhost"),
        ("postgresql+psycopg://u:p@127.0.0.1:5432/exposight", "localhost"),
        (
            "postgresql+psycopg://postgres:CHANGE_ME_GENERATE_A_STRONG_RANDOM_PASSWORD@db:5432/x",
            "placeholder",
        ),
        ("not a url", "not a valid database URL"),
    ],
)
def test_unsafe_database_url_is_reported(database_url, expected):
    problems = find_production_config_problems(database_url, GOOD_SUPABASE, GOOD_KEY)
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    ("supabase_url", "key", "expected"),
    [
        ("http://abcd1234.supabase.co", GOOD_KEY, "https://"),
        ("", GOOD_KEY, "https://"),
        ("https://your-production-project.supabase.co", GOOD_KEY, "placeholder"),
        (GOOD_SUPABASE, "", "SUPABASE_PUBLISHABLE_KEY"),
        (GOOD_SUPABASE, "CHANGE_ME_SUPABASE_ANON_PUBLIC_KEY", "SUPABASE_PUBLISHABLE_KEY"),
    ],
)
def test_unsafe_supabase_config_is_reported(supabase_url, key, expected):
    problems = find_production_config_problems(GOOD_DB, supabase_url, key)
    assert any(expected in p for p in problems), problems


def test_worker_mode_skips_supabase_checks():
    """supabase_url=None means the caller does not authenticate users."""
    assert find_production_config_problems(GOOD_DB, None, None) == []


def test_problem_messages_never_contain_secret_values():
    secret = "SuperSecretPw123"
    url = f"postgresql+psycopg://u:{secret}@localhost:5432/asm_test"
    problems = find_production_config_problems(url, "http://x", "CHANGE_ME")
    assert problems
    assert all(secret not in p for p in problems)


def test_unknown_environment_value_fails(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "prod")
    with pytest.raises(RuntimeError, match="ENVIRONMENT must be one of"):
        get_environment()


def test_environment_defaults_to_development(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert get_environment() == "development"


def test_enforce_refuses_test_database_in_production(production_env):
    production_env.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/asm_test")
    with pytest.raises(RuntimeError, match="Refusing to start with ENVIRONMENT=production"):
        enforce_production_config(check_auth=False)


def test_enforce_is_a_no_op_outside_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/asm_test")
    get_settings.cache_clear()
    try:
        enforce_production_config(check_auth=True)
    finally:
        get_settings.cache_clear()


def test_api_startup_refuses_placeholder_supabase_in_production(production_env):
    production_env.setenv("SUPABASE_URL", "https://your-production-project.supabase.co")
    with pytest.raises(RuntimeError, match="SUPABASE_URL still contains an example placeholder"):
        with TestClient(app):
            pass


def test_worker_startup_refuses_test_database_in_production(production_env):
    from asm.worker import __main__ as worker_main

    def _worker_must_not_start(*args, **kwargs):
        raise AssertionError("worker started: production guard did not run first")

    production_env.setattr(worker_main, "ASMWorker", _worker_must_not_start)
    production_env.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/asm_test")
    with pytest.raises(RuntimeError, match="test database"):
        worker_main.main()


def _docs_urls_in_fresh_process(environment: str) -> str:
    """Import asm.api.main in a new interpreter and print its docs settings."""
    env = {**os.environ, "ENVIRONMENT": environment}
    code = (
        "from asm.api.main import app; "
        "print(app.docs_url, app.redoc_url, app.openapi_url)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_api_docs_are_disabled_in_production():
    assert _docs_urls_in_fresh_process("production") == "None None None"


def test_api_docs_stay_enabled_in_development():
    assert _docs_urls_in_fresh_process("development") == "/docs /redoc /openapi.json"


def test_json_api_responses_get_nosniff_and_no_store():
    with TestClient(app) as client:
        resp = client.get("/no-such-api-route")
    assert resp.status_code == 404
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"


def test_static_assets_stay_cacheable():
    with TestClient(app) as client:
        resp = client.get("/static/css/app.css")
    assert resp.status_code == 200
    assert "no-store" not in resp.headers.get("Cache-Control", "")


@pytest.mark.parametrize(
    ("supabase_url", "expected"),
    [
        ("https://abcd.supabase.co", "https://abcd.supabase.co"),
        ("https://abcd.supabase.co/some/path?q=1", "https://abcd.supabase.co"),
        ("https://abcd.supabase.co:8443", "https://abcd.supabase.co:8443"),
        ("http://abcd.supabase.co", None),
        ("javascript:alert(1)", None),
        ("abcd.supabase.co", None),
        ("https://user:pw@abcd.supabase.co", None),
        ("https://abcd.supabase.co;script-src *", None),
        ("https://abcd.supabase.co:notaport", None),
        ("", None),
    ],
)
def test_supabase_csp_origin_accepts_only_https_hostnames(supabase_url, expected):
    assert supabase_csp_origin(supabase_url) == expected


def test_csp_never_contains_injected_directive():
    csp = build_csp_header("https://abcd.supabase.co; script-src https://evil.example")
    assert "evil.example" not in csp
    assert "connect-src 'self';" in csp
