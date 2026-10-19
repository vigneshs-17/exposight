"""IC-1: fixes for the independent check of 2026-10-19 (F2-F5, F7-F10, F13).

The F1 lock tests are in test_dependency_lock.py.
"""

import logging
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from asm.api import routes
from asm.api.main import app
from asm.auth.jwks import JWKSUnavailableError
from asm.db.session import get_db
from asm.logredact import install_log_redaction, redact
from asm.ratelimit import UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP
from asm.worker.worker import ASMWorker
from tests import test_auth
from tests.test_auth import _error_response, _jwks_manager_with, _ok_response

# Shared key and settings fixtures from the JWKS tests.
ec_key_pair = test_auth.ec_key_pair
auth_settings = test_auth.auth_settings

ROOT = Path(__file__).resolve().parent.parent
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=()"


def _yielding(session):
    """A generator dependency, as FastAPI expects for get_db overrides."""

    def _get_db():
        yield session

    return _get_db


class CountingSession:
    """Stands in for a DB session; counts the health check's SELECT 1."""

    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def execute(self, *args, **kwargs):
        self.calls += 1
        if self.fail:
            raise RuntimeError("database down")


@pytest.fixture
def fake_db():
    session = CountingSession()
    app.dependency_overrides[get_db] = _yielding(session)
    yield session
    app.dependency_overrides.pop(get_db, None)


# --- F2: GET and HEAD on / and /health ---------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/health"])
def test_head_matches_get_status_without_a_body(path, fake_db):
    with TestClient(app) as client:
        got = client.get(path)
        head = client.head(path)
    assert got.status_code == 200
    assert head.status_code == got.status_code
    assert head.content == b""
    assert head.headers["content-type"] == got.headers["content-type"]


# --- F3: the per-IP limit covers every request without a verified identity -------------


def test_invalid_authorization_header_does_not_bypass_the_ip_limit():
    junk = {"Authorization": "Bearer junk"}
    with TestClient(app) as client:
        for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
            assert client.get("/", headers=junk).status_code == 200
        blocked = client.get("/", headers=junk)
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["Retry-After"]) <= 60


def test_requests_with_and_without_a_header_share_one_ip_budget():
    with TestClient(app) as client:
        for i in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
            headers = {"Authorization": "x"} if i % 2 else {}
            assert client.get("/privacy", headers=headers).status_code == 200
        assert client.get("/terms").status_code == 429
        assert client.get("/terms", headers={"Authorization": "x"}).status_code == 429


def test_a_rejected_token_is_charged_once_not_twice(monkeypatch):
    """get_current_user already charges a 401; the middleware must not charge it again."""
    from fastapi import HTTPException

    from asm.api import deps
    from asm.api.deps import get_current_user

    def reject(*args):
        raise HTTPException(status_code=401, detail="bad token")

    monkeypatch.setattr(deps, "_authenticate", reject)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_db] = lambda: iter([None])
    try:
        with TestClient(app) as client:
            junk = {"Authorization": "Bearer junk"}
            for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP):
                assert client.get("/orgs", headers=junk).status_code == 401
            assert client.get("/orgs", headers=junk).status_code == 429
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.db
def test_verified_users_do_not_use_the_ip_budget(client):
    auth = {"Authorization": "Bearer stub"}
    for _ in range(UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP + 5):
        assert client.get("/orgs", headers=auth).status_code == 200
    # The IP budget is untouched for anonymous traffic from the same address.
    assert client.get("/").status_code == 200


# --- F4: /health caches the database check for 2 s -------------------------------------


def test_health_db_check_is_cached_for_two_seconds(fake_db, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(routes.time, "monotonic", lambda: clock[0])
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        clock[0] += 1.9
        assert client.get("/health").status_code == 200
        assert fake_db.calls == 1
        clock[0] += 0.2  # 2.1 s after the first check
        assert client.get("/health").status_code == 200
    assert fake_db.calls == 2


def test_health_failure_is_cached_too_and_recovers(monkeypatch):
    clock = [5000.0]
    monkeypatch.setattr(routes.time, "monotonic", lambda: clock[0])
    down = CountingSession(fail=True)
    app.dependency_overrides[get_db] = _yielding(down)
    try:
        with TestClient(app) as client:
            assert client.get("/health").status_code == 503
            assert client.get("/health").status_code == 503
            assert down.calls == 1
            up = CountingSession()
            app.dependency_overrides[get_db] = _yielding(up)
            clock[0] += 2.5
            assert client.get("/health").status_code == 200
            assert up.calls == 1
    finally:
        app.dependency_overrides.pop(get_db, None)


# --- F5: Permissions-Policy on every response -------------------------------------------


@pytest.mark.parametrize(
    ("path", "accept"),
    [
        ("/", "text/html"),
        ("/app", "text/html"),
        ("/privacy", "text/html"),
        ("/health", "application/json"),
        ("/static/css/app.css", "text/css"),
        ("/no-such-page", "application/json"),
        ("/no-such-page", "text/html"),
        ("/orgs", "application/json"),
    ],
)
def test_permissions_policy_on_every_response(path, accept, fake_db):
    with TestClient(app) as client:
        response = client.get(path, headers={"Accept": accept})
    assert response.headers["Permissions-Policy"] == PERMISSIONS_POLICY


# --- F7: log redaction patterns ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "secret", "expected"),
    [
        (
            "connect postgresql+psycopg://app:S3cretPw@db:5432/asm failed",
            "S3cretPw",
            "connect postgresql+psycopg://app:[redacted]@db:5432/asm failed",
        ),
        ("smtp://mailer:p%40ss@mail.example.net:587", "p%40ss", None),
        ("password: hunter2", "hunter2", "password: [redacted]"),
        ("SMTP_PASSWORD=hunter2 set", "hunter2", "SMTP_PASSWORD=[redacted] set"),
        (
            '{"access_token": "opaque123", "x": 1}',
            "opaque123",
            '{"access_token": "[redacted]", "x": 1}',
        ),
        ('{"refresh_token":"r-tok"}', "r-tok", '{"refresh_token":"[redacted]"}'),
        ("token=deadbeef claim", "deadbeef", "token=[redacted] claim"),
    ],
)
def test_redactor_masks_more_secret_shapes(raw, secret, expected):
    out = redact(raw)
    assert secret not in out
    if expected is not None:
        assert out == expected


@pytest.mark.parametrize(
    "safe",
    [
        "UPDATE scan_runs SET claim_token = :token WHERE id = :id",
        "unformatted log message password=%s token=%r",
        "Claimed scan_run_id=4 domain_id=2 attempt=1/3 lease=1a2b3c4d",
        "https://exposight.dev/app",
    ],
)
def test_redactor_leaves_ordinary_text_alone(safe):
    assert redact(safe) == safe


# --- F8: stale JWKS keys are served for at most 24 h ------------------------------------


def _manager_at(monkeypatch, ec_jwk, auth_settings):
    mock_client = MagicMock()
    mock_client.get.return_value = _ok_response({"keys": [ec_jwk]})
    manager = _jwks_manager_with(mock_client, auth_settings, cache_ttl=60.0)
    clock = [1000.0]
    monkeypatch.setattr("asm.auth.jwks.time.monotonic", lambda: clock[0])
    assert manager.get_signing_key("test-ec-kid") is not None
    mock_client.get.return_value = _error_response()
    return manager, clock


def test_stale_jwks_key_is_served_within_24_hours(ec_key_pair, auth_settings, monkeypatch):
    manager, clock = _manager_at(monkeypatch, ec_key_pair[2], auth_settings)
    clock[0] += 23 * 3600
    assert manager.get_signing_key("test-ec-kid") is not None


def test_stale_jwks_key_fails_closed_after_24_hours(ec_key_pair, auth_settings, monkeypatch):
    manager, clock = _manager_at(monkeypatch, ec_key_pair[2], auth_settings)
    clock[0] += 24 * 3600 + 1
    with pytest.raises(JWKSUnavailableError):
        manager.get_signing_key("test-ec-kid")


def test_stale_cap_also_applies_during_backoff(ec_key_pair, auth_settings, monkeypatch):
    """A failed fetch just before the cap starts a backoff; the cap still applies inside it."""
    manager, clock = _manager_at(monkeypatch, ec_key_pair[2], auth_settings)
    clock[0] += 24 * 3600 - 5
    assert manager.get_signing_key("test-ec-kid") is not None  # fetch fails, backoff starts
    clock[0] += 6  # past the cap, still inside the backoff window
    with pytest.raises(JWKSUnavailableError):
        manager.get_signing_key("test-ec-kid")


# --- F9: the worker logs a shortened lease id, not the claim token ----------------------


def test_worker_claim_log_uses_a_short_lease_id(caplog):
    install_log_redaction()
    token = uuid.UUID("1a2b3c4d-5e6f-4a1b-9c2d-0123456789ab")
    worker = ASMWorker(engine=MagicMock(), runner=MagicMock())
    for step in (
        "reclaim_stale_leases_and_poison_pills",
        "expire_operator_overrides",
        "reverify_due_domains",
        "schedule_due_scans",
        "deliver_pending_alerts",
        "purge_retention_if_due",
        "execute_scan_run",
    ):
        setattr(worker, step, MagicMock())
    worker.claim_next_job = MagicMock(return_value=(7, 3, token, 1, 3))

    with caplog.at_level(logging.INFO, logger="asm.worker"):
        assert worker.run_poll_cycle() is True

    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("Claimed"))
    assert "lease=1a2b3c4d" in line
    assert "token=" not in line
    assert str(token) not in line


# --- F10: Caddy drops Via, and Server on the HTTP redirect ------------------------------


def test_caddyfile_drops_via_and_serves_its_own_https_redirect():
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "header -Via" in caddyfile
    http_block = caddyfile.split("http://{$DOMAIN} {", 1)[1].split("}\n", 1)[0]
    assert "header -Server" in http_block
    assert "redir https://{host}{uri} 308" in http_block


# --- F13: robots.txt ----------------------------------------------------------------------


def test_robots_txt_allows_the_site_and_disallows_the_dashboard():
    with TestClient(app) as client:
        response = client.get("/robots.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    lines = response.text.splitlines()
    assert lines[0] == "User-agent: *"
    assert "Allow: /" in lines
    assert "Disallow: /app" in lines


def test_head_routes_do_not_duplicate_openapi_operation_ids():
    """HEAD handlers are hidden from the schema, so GET keeps a unique operation id."""
    import warnings

    app.openapi_schema = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            schema = app.openapi()
    finally:
        app.openapi_schema = None
    assert "get" in schema["paths"]["/health"]
    assert "head" not in schema["paths"]["/health"]
