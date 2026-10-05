"""Playwright browser test configuration and shared fixtures.

Provides:
- Settings patch pointing SUPABASE_URL to https://auth.test-asm.local.
- Database sessionmaker bound to db_engine with clean_db truncation.
- Synthetic token registry and make_fake_jwt helper from tests.browser.helpers.
- Overridden get_current_user dependency that authenticates tokens from TOKEN_REGISTRY.
- Live uvicorn server in a daemon thread on an ephemeral port.
- Playwright page fixture with CSP violation capture, console error tracking,
  Supabase auth routing, response monitoring, request abortion guard,
  and failure tracing/screenshots.
- auth_events fixture exposing refresh grant calls.
- Autouse patch forbidding real DNS lookups in browser tests.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Annotated, Any
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
import uvicorn
from fastapi import Header, HTTPException, status
from playwright.sync_api import BrowserContext, Page, Route, sync_playwright
from sqlalchemy.orm import Session, sessionmaker

from asm.api.deps import get_current_user, reset_auth_dependencies
from asm.api.main import app
from asm.db.models import User
from asm.db.session import get_db
from tests.browser.helpers import (
    REFRESH_REGISTRY,
    TOKEN_REGISTRY,
    make_fake_jwt,
)

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def forbid_real_dns():
    """Autouse fixture ensuring no real DNS lookups are attempted during browser tests."""

    def _fail_dns(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("real DNS lookup attempted in a browser test")

    with patch("asm.api.routes.check_dns_txt_verification", side_effect=_fail_dns) as mock_dns:
        yield mock_dns


@pytest.fixture(autouse=True)
def configure_browser_auth_settings():
    """Configure environment variables for Supabase auth in browser tests."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://auth.test-asm.local",
            "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_test",
        },
    ):
        reset_auth_dependencies()
        yield
        reset_auth_dependencies()


@pytest.fixture(scope="session")
def browser_session_factory(db_engine):
    """Sessionmaker bound to db_engine for live server thread requests."""
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def auth_events() -> list[dict[str, str]]:
    """List recording synthetic token refresh events."""
    return []


@pytest.fixture
def override_db_and_auth(browser_session_factory, clean_db):
    """Override get_db and get_current_user for the live server during tests."""

    def _override_get_db() -> Generator[Session, None, None]:
        with browser_session_factory() as session:
            yield session

    def _override_get_current_user(
        authorization: Annotated[str | None, Header()] = None,
    ) -> User:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization.removeprefix("Bearer ").strip()
        user_id = TOKEN_REGISTRY.get(token)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or unrecognized test token",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        with browser_session_factory() as session:
            user = session.get(User, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                )
            return user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    yield
    app.dependency_overrides.clear()
    TOKEN_REGISTRY.clear()
    REFRESH_REGISTRY.clear()


@pytest.fixture
def live_server(override_db_and_auth) -> Generator[str, None, None]:
    """Start uvicorn on an ephemeral port in a daemon thread and yield its base URL."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Bounded wait for server to start
    deadline = time.time() + 10.0
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    if not server.started or not server.servers:
        raise RuntimeError("Live uvicorn server failed to start within 10 seconds")

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.should_exit = True
    thread.join(timeout=5.0)


@pytest.fixture
def make_page(
    live_server: str,
    browser_session_factory,
    auth_events: list[dict[str, str]],
    request: pytest.FixtureRequest,
) -> Generator[Callable[..., Generator[Page, None, None]], None, None]:
    """Factory fixture returning a context manager that creates a Page with standard guards."""
    headed = os.getenv("BROWSER_HEADED", "0") == "1"

    @contextmanager
    def _factory(
        allowed_error_statuses: tuple[int, ...] = (), **context_kwargs: Any
    ) -> Generator[Page, None, None]:
        """allowed_error_statuses: extra HTTP statuses a test expects the browser to log
        (e.g. 403 for a suspended account). Empty by default, so every other test keeps
        the strict console guard."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not headed)
            context: BrowserContext = browser.new_context(**context_kwargs)

            output_dir = os.path.join("output", "playwright")
            os.makedirs(output_dir, exist_ok=True)
            context.tracing.start(screenshots=True, snapshots=True, sources=True)

            page_instance = context.new_page()

            # Capture CSP violations in window.__cspViolations
            page_instance.add_init_script(
                """
                window.__cspViolations = [];
                document.addEventListener('securitypolicyviolation', function(e) {
                    window.__cspViolations.push({
                        blockedURI: e.blockedURI,
                        violatedDirective: e.violatedDirective,
                        originalPolicy: e.originalPolicy
                    });
                });
                """
            )

            console_errors: list[str] = []
            page_errors: list[str] = []
            unexpected_responses: list[str] = []

            def _on_console(msg):
                if msg.type == "error":
                    text = msg.text
                    if "favicon.ico" in text:
                        return
                    # Only ignore status of 401 / 422 messages (plus HTMX response error codes)
                    if (
                        "status of 401" in text
                        or "status of 422" in text
                        or "Response Status Error Code 401" in text
                        or "Response Status Error Code 422" in text
                    ):
                        return
                    if any(
                        f"status of {code}" in text or f"Response Status Error Code {code}" in text
                        for code in allowed_error_statuses
                    ):
                        return
                    console_errors.append(text)

            def _on_page_error(exc):
                page_errors.append(str(exc))

            def _on_response(resp):
                url = resp.url
                if url.startswith(live_server):
                    status_code = resp.status
                    path = urlparse(url).path
                    if status_code >= 500:
                        unexpected_responses.append(f"HTTP {status_code} from {url}")
                    elif status_code == 404 and not path.endswith("favicon.ico"):
                        unexpected_responses.append(f"HTTP 404 from {url}")

            page_instance.on("console", _on_console)
            page_instance.on("pageerror", _on_page_error)
            page_instance.on("response", _on_response)

            aborted_requests: list[str] = []
            unexpected_auth_calls: list[str] = []

            def _route_handler(route: Route):
                req = route.request
                url = req.url

                # 1. Supabase auth mock
                if url.startswith("https://auth.test-asm.local/"):
                    if "/auth/v1/logout" in url:
                        # Sign-out: Supabase answers 204 No Content.
                        route.fulfill(status=204, body="")
                        return
                    if "token?grant_type=password" in url:
                        try:
                            post_data = req.post_data_json or {}
                        except Exception:
                            post_data = {}
                        email = (post_data.get("email") or "").strip().lower()

                        with browser_session_factory() as session:
                            user = session.query(User).filter(User.email == email).first()

                        if not user:
                            route.fulfill(
                                status=400,
                                content_type="application/json",
                                body=json.dumps(
                                    {
                                        "error": "invalid_grant",
                                        "error_description": "User not found",
                                    }
                                ),
                            )
                            return

                        fake_token = make_fake_jwt(user)
                        refresh_tok = f"ref_{fake_token}"
                        REFRESH_REGISTRY[refresh_tok] = user.id
                        user_sub = str(user.id)
                        route.fulfill(
                            status=200,
                            content_type="application/json",
                            body=json.dumps(
                                {
                                    "access_token": fake_token,
                                    "token_type": "bearer",
                                    "expires_in": 3600,
                                    "refresh_token": refresh_tok,
                                    "user": {
                                        "id": user_sub,
                                        "email": user.email,
                                        "aud": "authenticated",
                                        "role": "authenticated",
                                    },
                                }
                            ),
                        )
                        return

                    if "token?grant_type=refresh_token" in url:
                        try:
                            post_data = req.post_data_json or {}
                        except Exception:
                            post_data = {}
                        old_refresh = (post_data.get("refresh_token") or "").strip()
                        user_id = REFRESH_REGISTRY.get(old_refresh)

                        if not user_id:
                            route.fulfill(
                                status=400,
                                content_type="application/json",
                                body=json.dumps(
                                    {
                                        "error": "invalid_grant",
                                        "error_description": "Unknown refresh token",
                                    }
                                ),
                            )
                            return

                        with browser_session_factory() as session:
                            user = session.get(User, user_id)

                        if not user:
                            route.fulfill(
                                status=400,
                                content_type="application/json",
                                body=json.dumps(
                                    {
                                        "error": "invalid_grant",
                                        "error_description": "User not found",
                                    }
                                ),
                            )
                            return

                        new_access = make_fake_jwt(user)
                        new_refresh = f"ref_{new_access}"
                        REFRESH_REGISTRY[new_refresh] = user.id
                        auth_events.append({"old_refresh": old_refresh, "new_access": new_access})

                        route.fulfill(
                            status=200,
                            content_type="application/json",
                            body=json.dumps(
                                {
                                    "access_token": new_access,
                                    "token_type": "bearer",
                                    "expires_in": 3600,
                                    "refresh_token": new_refresh,
                                    "user": {
                                        "id": str(user.id),
                                        "email": user.email,
                                        "aud": "authenticated",
                                        "role": "authenticated",
                                    },
                                }
                            ),
                        )
                        return

                    unexpected_auth_calls.append(f"{req.method} {url}")
                    route.fulfill(
                        status=500,
                        content_type="application/json",
                        body=json.dumps({"error": "unexpected_auth_call", "url": url}),
                    )
                    return

                # 2. Local app server requests
                if url.startswith(live_server):
                    route.continue_()
                    return

                # 3. Disallowed external network egress
                aborted_requests.append(url)
                route.abort()

            page_instance.route("**", _route_handler)

            try:
                yield page_instance
            finally:
                # Failure artifacts (screenshots and trace)
                test_failed = hasattr(request.node, "rep_call") and request.node.rep_call.failed
                test_name = request.node.name
                if test_failed:
                    screenshot_path = os.path.join(output_dir, f"{test_name}.png")
                    trace_path = os.path.join(output_dir, f"{test_name}_trace.zip")
                    try:
                        page_instance.screenshot(path=screenshot_path)
                    except Exception as e:
                        logger.warning("Failed to capture failure screenshot: %s", e)
                    try:
                        context.tracing.stop(path=trace_path)
                    except Exception as e:
                        logger.warning("Failed to save trace: %s", e)
                else:
                    try:
                        context.tracing.stop()
                    except Exception:
                        pass

                # Collect CSP violations from page context
                csp_violations = []
                try:
                    csp_violations = page_instance.evaluate("window.__cspViolations || []")
                except Exception:
                    pass

                context.close()
                browser.close()

                # Teardown assertions
                assert len(csp_violations) == 0, f"CSP violations detected: {csp_violations}"
                assert len(console_errors) == 0, f"Console errors detected: {console_errors}"
                assert len(page_errors) == 0, f"Page errors detected: {page_errors}"
                assert len(unexpected_responses) == 0, (
                    f"Unexpected server responses detected: {unexpected_responses}"
                )
                assert len(unexpected_auth_calls) == 0, (
                    f"Unexpected auth calls: {unexpected_auth_calls}"
                )
                assert len(aborted_requests) == 0, (
                    f"External requests attempted and aborted: {aborted_requests}"
                )

    yield _factory


@pytest.fixture
def page(
    make_page: Callable[..., Generator[Page, None, None]],
) -> Generator[Page, None, None]:
    """Default Page fixture using make_page() without arguments."""
    with make_page() as p:
        yield p


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Store test outcome in item.rep_call for conditional artifact generation."""
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
