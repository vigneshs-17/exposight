"""RFC 9116 security.txt at /.well-known/security.txt."""

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

from asm.api.deps import reset_auth_dependencies
from asm.api.main import app

ENV = {"SUPABASE_URL": "https://testproj.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "anon_key_1"}


def _get(path: str):
    with patch.dict(os.environ, ENV):
        reset_auth_dependencies()
        with TestClient(app) as client:
            return client.get(path)


def _fields(body: str) -> dict[str, str]:
    return dict(line.split(": ", 1) for line in body.splitlines() if line and not line.startswith("#"))


def test_security_txt_served_as_plain_text_with_required_fields():
    resp = _get("/.well-known/security.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"
    fields = _fields(resp.text)
    assert fields["Contact"] == "https://github.com/vigneshs-17/exposight/security/advisories/new"
    assert fields["Preferred-Languages"] == "en"
    assert fields["Canonical"] == "https://exposight.dev/.well-known/security.txt"


def test_security_txt_expires_in_future_and_under_one_year():
    expires = datetime.fromisoformat(_fields(_get("/.well-known/security.txt").text)["Expires"])
    now = datetime.now(UTC)
    assert now < expires < now + timedelta(days=365)
    assert _get("/.well-known/security.txt").text.count("Expires:") == 1


def test_security_txt_carries_security_headers():
    resp = _get("/.well-known/security.txt")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
