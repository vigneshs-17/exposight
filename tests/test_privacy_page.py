"""Public /privacy page: honest about what is stored, who processes it and for how long."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from asm.api.deps import reset_auth_dependencies
from asm.api.main import app
from asm.retention import INVITE_RETENTION, NOTIFICATION_RETENTION, SCAN_RETENTION

ENV = {"SUPABASE_URL": "https://testproj.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "anon_key_1"}


def _get(path: str):
    with patch.dict(os.environ, ENV):
        reset_auth_dependencies()
        with TestClient(app) as client:
            return client.get(path)


def test_privacy_page_served_with_strict_csp_and_no_auth():
    resp = _get("/privacy")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    html = resp.text
    assert "<script" not in html and "style=" not in html
    assert '<link rel="stylesheet" href="/static/css/landing.css">' in html


def test_privacy_lists_stored_data_and_processors():
    html = _get("/privacy").text
    for phrase in (
        "Supabase Auth",
        "organisations, memberships and roles",
        "verification",
        "scan results",
        "audit log",
        "alert recipient",
        "Microsoft Azure",
        "crt.sh",
        "Cert Spotter",
        "email provider",
        "invite-only",
        "student",
    ):
        assert phrase.lower() in html.lower(), phrase
    assert "https://github.com/vigneshs-17/exposight/security/advisories/new" in html


def test_privacy_retention_matches_purge_code():
    html = _get("/privacy").text
    assert f"{SCAN_RETENTION.days} days" in html
    assert f"{NOTIFICATION_RETENTION.days} days" in html
    assert f"{INVITE_RETENTION.days} days" in html
    assert "off unless the operator turns it on" in html
    assert "Audit log entries are never purged" in html


@pytest.mark.parametrize("path", ["/", "/terms", "/app"])
def test_footers_link_to_privacy(path):
    assert 'href="/privacy"' in _get(path).text
