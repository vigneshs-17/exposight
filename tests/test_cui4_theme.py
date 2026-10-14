"""C-UI-4: /terms on the landing theme, favicon, og:image, /app meta tags, landing.js label."""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from asm.api.deps import reset_auth_dependencies
from asm.api.main import app

ROOT = Path(__file__).resolve().parent.parent / "src" / "asm"
STATIC = ROOT / "static"
OG_URL = "https://exposight.dev/static/og-image.png"
ICON = '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">'


@pytest.fixture(scope="module")
def client():
    with patch.dict(
        os.environ,
        {"SUPABASE_URL": "https://testproj.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "anon_key_1"},
    ):
        reset_auth_dependencies()
        with TestClient(app) as test_client:
            yield test_client
        reset_auth_dependencies()


def test_terms_uses_landing_theme_only(client):
    html = client.get("/terms").text
    assert re.findall(r'<link rel="stylesheet" href="([^"]+)"', html) == ["/static/css/landing.css"]
    assert 'class="brand-mark"' in html
    assert "brand-badge" not in html and ">EXP<" not in html
    css = (STATIC / "css" / "landing.css").read_text(encoding="utf-8")
    assert ".terms-content {" in css and ".terms-updated {" in css


def test_favicon_is_a_plain_svg_served_as_svg(client):
    svg = (STATIC / "favicon.svg").read_text(encoding="utf-8")
    assert svg.startswith("<svg") and "<script" not in svg.lower()
    assert "href" not in svg and "url(" not in svg  # no external or embedded references
    resp = client.get("/static/favicon.svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/svg+xml")


@pytest.mark.parametrize("path", ["/", "/terms", "/app"])
def test_every_page_links_the_favicon(client, path):
    assert ICON in client.get(path).text


def test_error_page_links_the_favicon(client):
    assert ICON in client.get("/no-such-page", headers={"Accept": "text/html"}).text


def test_og_image_is_a_1200x630_png():
    data = (STATIC / "og-image.png").read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", data[16:24]) == (1200, 630)


@pytest.mark.parametrize("path", ["/", "/terms"])
def test_landing_and_terms_carry_large_social_card(client, path):
    html = client.get(path).text
    assert f'<meta property="og:image" content="{OG_URL}">' in html
    assert '<meta name="twitter:card" content="summary_large_image">' in html
    assert f'<meta name="twitter:image" content="{OG_URL}">' in html
    assert '<meta property="og:image:width" content="1200">' in html


def test_app_has_description_and_noindex(client):
    html = client.get("/app").text
    assert re.search(r'<meta name="description" content="[^"]{20,}">', html)
    assert '<meta name="robots" content="noindex">' in html


def test_landing_js_checks_key_names_only():
    js = (STATIC / "js" / "landing.js").read_text(encoding="utf-8")
    assert "/^sb-.+-auth-token$/" in js
    assert 'textContent = "Open dashboard"' in js
    for forbidden in ("getItem", "fetch(", "XMLHttpRequest", "JSON.parse", "innerHTML"):
        assert forbidden not in js, f"landing.js must not use {forbidden}"
