"""C-UI-4: themed HTML error pages for browser page requests, JSON everywhere else, and the
full security header set on every 404, 403 and 500 (the 500 handler runs outside the
headers middleware, so before C-UI-4 a 500 carried no security headers at all)."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from asm.api.deps import get_active_user, get_current_auth_settings, reset_auth_dependencies
from asm.api.main import (
    app,
    apply_response_security_headers,
    generic_exception_handler,
    page_aware_http_exception_handler,
)
from asm.api.routes_ui import build_csp_header

SUPABASE_URL = "https://testproj.supabase.co"
HTML = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
LEAK_MARKER = "internal-detail-marker"
PAGE_CSP = build_csp_header(SUPABASE_URL)


@pytest.fixture(autouse=True)
def auth_env():
    with patch.dict(
        os.environ, {"SUPABASE_URL": SUPABASE_URL, "SUPABASE_PUBLISHABLE_KEY": "anon_key_1"}
    ):
        reset_auth_dependencies()
        yield
        reset_auth_dependencies()


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def assert_security_headers(headers, csp: str) -> None:
    """The full set the middleware sets on an error response."""
    assert headers["Content-Security-Policy"] == csp
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


def assert_html_error_page(resp, status_code: int) -> None:
    assert resp.status_code == status_code
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    assert f"Error {status_code}" in body
    assert 'class="brand-mark"' in body
    assert 'href="/"' in body and 'href="/app"' in body
    assert '<meta name="robots" content="noindex">' in body
    assert 'rel="icon" href="/static/favicon.svg"' in body
    assert "<script" not in body and "style=" not in body
    assert_security_headers(resp.headers, PAGE_CSP)


def _request(path: str, accept: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"accept", accept.encode())],
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "scheme": "http",
        }
    )


# --- 404 through the real app ---------------------------------------------------------


def test_404_page_request_gets_html_page_without_echoing_the_path(client):
    resp = client.get(f"/no-such-page-{LEAK_MARKER}", headers={"Accept": HTML})
    assert_html_error_page(resp, 404)
    assert "Page not found" in resp.text
    assert LEAK_MARKER not in resp.text


def test_404_page_path_under_app_gets_html_page(client):
    assert_html_error_page(client.get("/app/missing", headers={"Accept": HTML}), 404)


def test_404_without_html_accept_stays_json(client):
    resp = client.get("/no-such-page", headers={"Accept": "application/json"})
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}
    assert_security_headers(resp.headers, "frame-ancestors 'none'")


@pytest.mark.parametrize(
    "path,csp",
    [
        ("/orgs/1/no-such-thing", "frame-ancestors 'none'"),
        ("/invites/no-such-thing/x", "frame-ancestors 'none'"),
        ("/ui/no-such-partial", PAGE_CSP),
        ("/static/css/missing.css", PAGE_CSP),
    ],
)
def test_404_on_api_partial_and_asset_paths_stays_json_even_for_html_accept(client, path, csp):
    resp = client.get(path, headers={"Accept": HTML})
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {"detail": "Not Found"}
    assert_security_headers(resp.headers, csp)


# --- 403 (no HTML page route raises 403, so the handler is called directly) -------------


def test_403_page_request_gets_html_page():
    resp = asyncio.run(
        page_aware_http_exception_handler(
            _request("/some-page", HTML), HTTPException(status_code=403, detail=LEAK_MARKER)
        )
    )
    assert_html_error_page(_as_client_response(resp), 403)
    assert "Access denied" in resp.body.decode()
    assert LEAK_MARKER not in resp.body.decode()


def test_403_api_request_keeps_json_detail_and_headers():
    resp = asyncio.run(
        page_aware_http_exception_handler(
            _request("/orgs/1", HTML), HTTPException(status_code=403, detail="Account suspended")
        )
    )
    # The handler returns FastAPI's JSON; the middleware adds the headers on the way out.
    assert resp.status_code == 403
    assert resp.body == b'{"detail":"Account suspended"}'
    apply_response_security_headers("/orgs/1", resp)
    assert_security_headers(resp.headers, "frame-ancestors 'none'")


def test_other_statuses_keep_fastapi_json_and_their_headers():
    exc = HTTPException(status_code=401, detail="x", headers={"WWW-Authenticate": "Bearer"})
    resp = asyncio.run(page_aware_http_exception_handler(_request("/some-page", HTML), exc))
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.media_type == "application/json"


# --- 500 through the real app (dependency override raises; no test-only route) ----------


def _boom():
    raise RuntimeError(LEAK_MARKER)


def test_500_page_request_gets_html_page_with_headers(client):
    app.dependency_overrides[get_current_auth_settings] = _boom
    resp = client.get("/terms", headers={"Accept": HTML})
    assert_html_error_page(resp, 500)
    assert "Something went wrong" in resp.text
    assert LEAK_MARKER not in resp.text and "Traceback" not in resp.text


def test_500_page_still_renders_when_auth_settings_are_the_failure():
    """The error page falls back to a CSP without the Supabase origin."""
    with patch("asm.api.main.get_current_auth_settings", side_effect=RuntimeError(LEAK_MARKER)):
        resp = asyncio.run(generic_exception_handler(_request("/terms", HTML), RuntimeError()))
    assert resp.status_code == 500
    assert resp.headers["Content-Security-Policy"] == build_csp_header("")
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_500_api_request_keeps_json_body_and_gets_headers(client):
    app.dependency_overrides[get_active_user] = _boom
    resp = client.get("/orgs", headers={"Accept": HTML, "Authorization": "Bearer x"})
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error. Please consult system logs."}
    assert LEAK_MARKER not in resp.text
    assert_security_headers(resp.headers, "frame-ancestors 'none'")


def test_500_json_for_non_html_accept_on_page_path(client):
    app.dependency_overrides[get_current_auth_settings] = _boom
    resp = client.get("/terms", headers={"Accept": "application/json"})
    assert resp.status_code == 500
    assert resp.headers["content-type"].startswith("application/json")
    assert_security_headers(resp.headers, "frame-ancestors 'none'")


class _ClientLike:
    """Adapter so a raw Response can go through assert_html_error_page."""

    def __init__(self, resp):
        self.status_code = resp.status_code
        self.headers = resp.headers
        self.text = resp.body.decode()


def _as_client_response(resp):
    return _ClientLike(resp)
