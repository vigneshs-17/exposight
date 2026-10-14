"""H-Hdr-1: clickjacking headers on every response and no `Server` header disclosure."""

from __future__ import annotations

import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient
from uvicorn.main import main as uvicorn_cli

from asm.api.deps import reset_auth_dependencies
from asm.api.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent
PATHS = ["/", "/app", "/terms", "/no-such-page"]


@pytest.fixture
def client():
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_1",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as test_client:
            yield test_client
        reset_auth_dependencies()


@pytest.mark.parametrize("path", PATHS)
def test_framing_is_denied_on_pages_and_404(client, path):
    resp = client.get(path)
    assert resp.status_code == (404 if path == "/no-such-page" else 200)
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "uvicorn" not in resp.headers.get("server", "").lower()


def test_page_csp_is_otherwise_unchanged(client):
    """The full page CSP still carries every directive; only API/404s get framing-only CSP."""
    csp = client.get("/app").headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'"):
        assert directive in csp
    assert client.get("/no-such-page").headers["Content-Security-Policy"] == (
        "frame-ancestors 'none'"
    )


def _api_command(compose_file: str) -> list[str]:
    config = yaml.safe_load((REPO_ROOT / compose_file).read_text(encoding="utf-8"))
    api = config["services"]["api"]
    assert api["entrypoint"] == ["uvicorn"]
    return list(api["command"])


@pytest.mark.parametrize("compose_file", ["compose.prod.yml", "docker-compose.yml"])
def test_compose_runs_uvicorn_without_server_header(compose_file):
    """Parse the api command with uvicorn's own CLI, then serve with that setting."""
    params = uvicorn_cli.make_context("uvicorn", _api_command(compose_file)).params
    assert params["server_header"] is False

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            log_level="warning",
            server_header=params["server_header"],
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10.0
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    try:
        port = server.servers[0].sockets[0].getsockname()[1]
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/no-such-page", timeout=5)  # noqa: S310
        headers = err.value.headers
        err.value.close()
        assert headers.get("Server") is None, f"Server header sent: {headers.get('Server')}"
        assert headers.get("X-Frame-Options") == "DENY"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def test_caddyfile_strips_server_header():
    lines = [
        ln.strip().lower()
        for ln in (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8").splitlines()
    ]
    assert "header -server" in lines
