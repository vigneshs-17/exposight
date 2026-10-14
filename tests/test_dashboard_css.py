"""C-UI-3: static checks on the dashboard stylesheet (app.css) restyled to DESIGN.md."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "src" / "asm"
APP_CSS = ROOT / "static" / "css" / "app.css"


def _css() -> str:
    return APP_CSS.read_text(encoding="utf-8")


def test_app_css_loads_only_local_fonts_that_exist():
    urls = re.findall(r"url\(['\"]?([^'\")]+)", _css())
    assert urls, "app.css has no @font-face url()"
    for url in urls:
        assert url.startswith("/static/fonts/"), f"non-local url in app.css: {url}"
        assert (ROOT / url.removeprefix("/")).is_file(), f"missing font file: {url}"
    assert "IBM Plex Sans" not in _css()


def test_app_css_uses_design_tokens():
    css = _css()
    for token, value in {
        "--bg": "#09090B",
        "--surface-2": "#121316",
        "--border": "#27272A",
        "--accent": "#22D3EE",
    }.items():
        assert f"{token}: {value};" in css, f"{token} is not {value}"
    panel = re.search(r"\.surface-panel \{(.*?)\}", css, re.S).group(1)
    assert "var(--surface-2)" in panel and "var(--border)" in panel


def test_app_css_defines_every_status_and_tier_chip():
    css = _css()
    for status in (
        "verified",
        "pending",
        "lapsed",
        "queued",
        "running",
        "succeeded",
        "failed",
        "skipped",
        "cancelled",
    ):
        assert f".status-{status}" in css, f".status-{status} missing"
    for tier in ("critical", "high", "medium", "low", "info"):
        assert f".tier-{tier} {{" in css, f".tier-{tier} missing"
    rule = lambda sel: re.search(re.escape(sel) + r"[^{]*\{(.*?)\}", css, re.S).group(1)  # noqa: E731
    assert "var(--ok)" in rule(".status-verified")
    assert "var(--medium)" in rule(".status-pending")
    assert "var(--critical)" in rule(".status-failed")


def test_app_css_turns_transitions_off_for_reduced_motion():
    match = re.search(r"@media \(prefers-reduced-motion: reduce\)\s*\{(.*?)\n\}", _css(), re.S)
    assert match, "no prefers-reduced-motion: reduce block"
    assert "transition: none !important" in match.group(1)
    assert "@keyframes" not in _css()


def test_dashboard_header_has_logo_and_controls():
    html = (ROOT / "templates" / "app.html").read_text(encoding="utf-8")
    assert 'class="brand-mark"' in html
    for element_id in ("org-switcher-select", "user-email-display", "signout-button"):
        assert f'id="{element_id}"' in html
    assert "style=" not in html and "<style" not in html


def test_hover_border_is_a_documented_token():
    css = _css()
    assert css.count("#3F3F46") == 1 and "--border-hover: #3F3F46;" in css
    design = (ROOT.parent.parent / "DESIGN.md").read_text(encoding="utf-8")
    for documented in ("--border-hover: #3F3F46", "#F87171", "#60A5FA"):
        assert documented in design, f"DESIGN.md does not document {documented}"
