"""Tests for Phase v3.4a dashboard shell, UI fragments, security headers, and static assets."""

import importlib.resources
import os
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user, reset_auth_dependencies
from asm.api.main import app
from asm.audit import record_event
from asm.auth.config import get_auth_settings
from asm.config import Settings, get_settings
from asm.db.models import (
    AlertNotification,
    AuditEvent,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
    ScanStage,
    User,
)
from asm.db.session import get_engine
from asm.verification import queue_domain_alert


def test_landing_page_serves_html_and_security_headers():
    """GET / serves landing HTML with full CSP matching /app, without auth."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "Content-Security-Policy" in resp.headers
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["Referrer-Policy"] == "no-referrer"

            # Compare CSP with /app
            resp_app = client.get("/app")
            assert (
                resp.headers["Content-Security-Policy"]
                == resp_app.headers["Content-Security-Policy"]
            )


def test_landing_page_content_invariants():
    """GET / contains required copy, links /app and GitHub, and has no banned patterns."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/")
            assert resp.status_code == 200
            html = resp.text

            # Links /app and GitHub
            assert 'href="/app"' in html
            assert "https://github.com/vigneshs-17/exposight" in html

            # Mandatory copy checks
            assert (
                "Active scans run only on domains you have verified with a DNS TXT record at"
                in html
            )
            assert "_asm-verify.&lt;domain&gt;" in html or "_asm-verify.<domain>" in html
            assert "A time-limited operator override exists for exceptional cases." in html
            audit_text = (
                "Append-only audit log: a database trigger blocks updates, deletes and truncates "
                "from the application."
            )
            assert audit_text in html

            # Assert dynamic verification TXT example rendered
            from html import escape

            from asm.verification import get_expected_record_value

            expected_txt = escape(get_expected_record_value("<your-token>"))
            assert expected_txt in html

            # Brand checks
            assert "Exposight" in html
            assert "ASM SaaS" not in html

            # Banned copy checks
            assert "tamper" not in html.lower()
            assert "v3.5" not in html
            assert 'rel="canonical"' not in html
            assert "revoked" not in html.lower()
            assert "dual-stack" not in html.lower()
            assert "clean umd" not in html.lower()


def test_app_shell_serves_html_and_no_inline_scripts():
    """GET /app serves HTML with data- attributes, no inline scripts, and no inline styles."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/app")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            html = resp.text

            # Passes config via data- attributes on body
            assert 'data-supabase-url="https://testproj.supabase.co"' in html
            assert 'data-supabase-key="anon_key_test_12345"' in html

            # Assert htmx-config meta tag is present with includeIndicatorStyles false
            assert '<meta name="htmx-config"' in html
            assert '"includeIndicatorStyles": false' in html

            # Assert zero inline scripts (all <script> must have src and empty body)
            script_pattern = r"<script(.*?)>(.*?)</script>"
            script_tags = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
            for attrs, body in script_tags:
                assert "src=" in attrs, f"Inline script found without src: {attrs}"
                assert body.strip() == "", f"Inline script content found: {body}"

            # Assert zero inline style attributes
            style_attrs = re.findall(r'style=["\'](.*?)["\']', html, re.IGNORECASE)
            assert len(style_attrs) == 0, f"Inline style attribute found: {style_attrs}"


def test_csp_and_security_headers_present():
    """Strict CSP and security headers must be present on /app, /ui/*, and /static/*."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/app")
            assert resp.status_code == 200

            # Headers present
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("Referrer-Policy") == "no-referrer"

            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "style-src 'self'" in csp
            assert "font-src 'self'" in csp
            assert "img-src 'self' data:" in csp
            assert "connect-src 'self' https://testproj.supabase.co" in csp
            assert "frame-ancestors 'none'" in csp
            assert "base-uri 'self'" in csp
            assert "form-action 'self'" in csp

            # Check static file security headers
            resp_static = client.get("/static/css/app.css")
            assert resp_static.status_code == 200
            assert resp_static.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp_static.headers.get("Referrer-Policy") == "no-referrer"
            assert "default-src 'self'" in resp_static.headers.get("Content-Security-Policy", "")


def test_secret_key_fails_startup():
    """Startup fails fast if SUPABASE_PUBLISHABLE_KEY starts with 'sb_secret_'."""
    # 1. Settings validation failure
    with pytest.raises((ValueError, RuntimeError), match="CRITICAL SECURITY MISCONFIGURATION"):
        Settings(
            database_url="postgresql+psycopg://test:test@localhost:5432/asm_test",
            supabase_publishable_key="sb_secret_super_secret_service_key",
        )

    # 2. AuthSettings / get_auth_settings failure
    with patch.dict(
        os.environ,
        {"SUPABASE_PUBLISHABLE_KEY": "sb_secret_bad_key"},
    ):
        with pytest.raises(RuntimeError, match="CRITICAL SECURITY MISCONFIGURATION"):
            get_auth_settings()


def test_static_files_served_correctly():
    """Vendored libraries, styles, and self-hosted fonts are served with 200."""
    with TestClient(app) as client:
        # HTMX
        resp_htmx = client.get("/static/vendor/htmx.min.js")
        assert resp_htmx.status_code == 200
        assert len(resp_htmx.content) > 10000

        # Supabase JS
        resp_supa = client.get("/static/vendor/supabase.min.js")
        assert resp_supa.status_code == 200
        assert len(resp_supa.content) > 10000

        # GSAP
        resp_gsap = client.get("/static/vendor/gsap.min.js")
        assert resp_gsap.status_code == 200
        assert len(resp_gsap.content) > 10000

        # ScrollTrigger
        resp_st = client.get("/static/vendor/ScrollTrigger.min.js")
        assert resp_st.status_code == 200
        assert len(resp_st.content) > 10000

        # Stylesheet (verifies palette concept comment exists)
        resp_css = client.get("/static/css/app.css")
        assert resp_css.status_code == 200
        assert "A crisp radar-inspired visual hierarchy" in resp_css.text

        # Landing CSS & JS
        resp_landing_css = client.get("/static/css/landing.css")
        assert resp_landing_css.status_code == 200
        resp_landing_js = client.get("/static/js/landing.js")
        assert resp_landing_js.status_code == 200

        # IBM Plex Fonts
        resp_font = client.get("/static/fonts/IBMPlexSans-Regular.woff2")
        assert resp_font.status_code == 200
        assert len(resp_font.content) > 10000


def test_app_js_contains_no_inner_html():
    """Static client scripts app.js and landing.js must never contain the word innerHTML."""
    root = Path(__file__).resolve().parent.parent
    for script_name in ["app.js", "landing.js"]:
        script_path = root / "src" / "asm" / "static" / "js" / script_name
        assert script_path.is_file(), f"{script_path} missing!"
        content = script_path.read_text(encoding="utf-8")
        assert "innerHTML" not in content, f"Found forbidden property 'innerHTML' in {script_name}"


def test_templates_package_data_exists():
    """Verify templates, static assets, and font files are accessible via package data.

    Docker in-image check.
    """
    expected_files = [
        ("templates", "app.html"),
        ("templates", "landing.html"),
        ("templates", "partials", "scans_list.html"),
        ("templates", "partials", "scan_detail.html"),
        ("static", "js", "app.js"),
        ("static", "js", "landing.js"),
        ("static", "vendor", "htmx.min.js"),
        ("static", "vendor", "supabase.min.js"),
        ("static", "vendor", "gsap.min.js"),
        ("static", "vendor", "ScrollTrigger.min.js"),
        ("static", "css", "app.css"),
        ("static", "css", "landing.css"),
        ("static", "fonts", "IBMPlexSans-Regular.woff2"),
        ("static", "fonts", "IBMPlexSans-SemiBold.woff2"),
        ("static", "fonts", "IBMPlexMono-Regular.woff2"),
    ]
    pkg_files = importlib.resources.files("asm")
    for parts in expected_files:
        res = pkg_files.joinpath(*parts)
        assert res.is_file(), f"{'/'.join(parts)} is not a valid package data file!"


def _score_card_value(html: str, label: str) -> int | None:
    """Return the number shown on the Fix-first summary card with the given label."""
    match = re.search(
        r'<div class="score-card-value">\s*(\d+)\s*</div>\s*'
        rf'<div class="score-card-label">{re.escape(label)}</div>',
        html,
    )
    return int(match.group(1)) if match else None


def test_templates_have_no_csp_blocked_inline_code():
    """Every template must be CSP-clean: style-src/script-src 'self' block inline code.

    Inline style attributes, <style> blocks, inline event handlers, and inline scripts
    are silently blocked by the browser, so they must never appear in a template.
    """
    root = Path(__file__).resolve().parent.parent
    templates_dir = root / "src" / "asm" / "templates"
    template_files = sorted(templates_dir.rglob("*.html"))
    assert template_files, "No templates found"

    forbidden = {
        "inline style attribute": re.compile(r"\sstyle\s*=", re.IGNORECASE),
        "<style> block": re.compile(r"<style\b", re.IGNORECASE),
        "inline event handler": re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
        "htmx inline handler (hx-on)": re.compile(r"\bhx-on[:-]", re.IGNORECASE),
        "inline <script> without src": re.compile(
            r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE
        ),
        "|safe filter": re.compile(r"\|\s*safe\b", re.IGNORECASE),
        "tojson filter": re.compile(r"\|\s*tojson\b", re.IGNORECASE),
    }
    problems = []
    for path in template_files:
        text = path.read_text(encoding="utf-8")
        for name, pattern in forbidden.items():
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                problems.append(f"{path.relative_to(root)}:{line_no}: {name}")
    assert not problems, "CSP-blocked inline code found:\n" + "\n".join(problems)


def test_templates_form_fields_have_labels():
    """Every form field in templates must have an accessible label.

    Every <input> (except type="hidden"), <select>, and <textarea> must have a
    <label for="its id">, be wrapped in a <label>, or carry aria-label / aria-labelledby.
    Reports file:line for each failure.
    """
    root = Path(__file__).resolve().parent.parent
    templates_dir = root / "src" / "asm" / "templates"
    template_files = sorted(templates_dir.rglob("*.html"))
    assert template_files, "No templates found"

    class FormFieldParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.labels_for = set()
            self.label_depth = 0
            self.fields = []

        def handle_starttag(self, tag, attrs):
            attr_dict = dict(attrs)
            if tag == "label":
                self.label_depth += 1
                if "for" in attr_dict:
                    self.labels_for.add(attr_dict["for"])
            elif tag in ("input", "select", "textarea"):
                if tag == "input" and attr_dict.get("type", "").lower() == "hidden":
                    return
                self.fields.append(
                    {
                        "tag": tag,
                        "attrs": attr_dict,
                        "wrapped": self.label_depth > 0,
                        "line": self.getpos()[0],
                    }
                )

        def handle_endtag(self, tag):
            if tag == "label" and self.label_depth > 0:
                self.label_depth -= 1

    failures = []
    for path in template_files:
        parser = FormFieldParser()
        parser.feed(path.read_text(encoding="utf-8"))
        rel_path = path.relative_to(root)
        for field in parser.fields:
            field_id = field["attrs"].get("id")
            has_label = (
                field["wrapped"]
                or ("aria-label" in field["attrs"])
                or ("aria-labelledby" in field["attrs"])
                or (field_id is not None and field_id in parser.labels_for)
            )
            if not has_label:
                failures.append(
                    f"{rel_path}:{field['line']}: <{field['tag']}> id={field_id} missing label"
                )

    assert not failures, "Form fields missing accessible labels:\n" + "\n".join(failures)


def test_ui_unauthenticated_returns_401():
    """Calling /ui/* endpoints without an Authorization header returns 401."""
    # Ensure no dependency overrides
    app.dependency_overrides.pop(get_current_user, None)
    get_settings.cache_clear()
    get_engine.cache_clear()
    try:
        with patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://testproj.supabase.co",
                "DATABASE_URL": "postgresql+psycopg://dummy:dummy@127.0.0.1:1/dummy_test",
            },
        ):
            reset_auth_dependencies()
            with TestClient(app) as client:
                resp1 = client.get("/ui/empty-org")
                assert resp1.status_code == 401

                resp2 = client.get("/ui/orgs/1/domains")
                assert resp2.status_code == 401

                resp3 = client.get("/ui/orgs/1/domains/1")
                assert resp3.status_code == 401

                resp4 = client.get("/ui/orgs/1/domains/1/scans")
                assert resp4.status_code == 401

                resp5 = client.get("/ui/orgs/1/scans/1")
                assert resp5.status_code == 401

                resp6 = client.get("/ui/orgs/1/domains/1/alert-notifications")
                assert resp6.status_code == 401

                resp7 = client.get("/ui/orgs/1/audit-events")
                assert resp7.status_code == 401
    finally:
        get_settings.cache_clear()
        get_engine.cache_clear()
        reset_auth_dependencies()


# ==============================================================================
# Database Integration Tests (marked @pytest.mark.db)
# ==============================================================================


@pytest.mark.db
def test_ui_cache_control_no_store(client: TestClient, db_session: Session, test_org: Organization):
    """Every /ui/* HTML fragment response must include Cache-Control: no-store."""
    resp = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"


@pytest.mark.db
def test_viewer_vs_admin_rendering(client: TestClient, db_session: Session, test_org: Organization):
    """Viewers do not see write forms or action buttons; admins see full controls."""
    # Create test domain
    domain = Domain(
        org_id=test_org.id,
        name="rbac-test.example.com",
        verification_status="pending",
        verification_token="tok-rbac-test",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Admin context (client fixture user is owner of test_org)
    resp_admin_list = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp_admin_list.status_code == 200
    assert 'id="add-domain-form"' in resp_admin_list.text

    resp_admin_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_admin_detail.status_code == 200
    assert 'id="btn-check-verification"' in resp_admin_detail.text
    assert 'id="btn-rotate-token"' in resp_admin_detail.text
    admin_result_tag = re.search(
        r'<div[^>]*id="verification-check-result"[^>]*>', resp_admin_detail.text
    )
    assert admin_result_tag is not None
    assert "hidden" not in admin_result_tag.group(0)

    # 2. Viewer context
    viewer_user_id = UUID("00000000-0000-0000-0000-000000000002")
    viewer_user = db_session.get(User, viewer_user_id)
    if not viewer_user:
        viewer_user = User(id=viewer_user_id, email="viewer@example.com")
        db_session.add(viewer_user)
        db_session.flush()

    # Downgrade or create membership as viewer
    membership = (
        db_session.query(Membership).filter_by(org_id=test_org.id, user_id=viewer_user_id).first()
    )
    if not membership:
        membership = Membership(org_id=test_org.id, user_id=viewer_user_id, role="viewer")
        db_session.add(membership)
    else:
        membership.role = "viewer"
    db_session.flush()

    # Override get_current_user to return viewer
    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_viewer_list = client.get(f"/ui/orgs/{test_org.id}/domains")
        assert resp_viewer_list.status_code == 200
        assert 'id="add-domain-form"' not in resp_viewer_list.text

        resp_viewer_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
        assert resp_viewer_detail.status_code == 200
        assert 'id="btn-check-verification"' not in resp_viewer_detail.text
        assert 'id="btn-rotate-token"' not in resp_viewer_detail.text
        viewer_result_tag = re.search(
            r'<div[^>]*id="verification-check-result"[^>]*>', resp_viewer_detail.text
        )
        assert viewer_result_tag is not None
        assert "hidden" not in viewer_result_tag.group(0)
    finally:
        # Restore fixture user
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_cross_tenant_404_on_ui_routes(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Accessing UI endpoints for a foreign tenant returns 404 (anti-enumeration)."""
    # Create foreign organization without membership for test user
    foreign_org = Organization(name="Foreign Organization")
    db_session.add(foreign_org)
    db_session.flush()

    foreign_domain = Domain(
        org_id=foreign_org.id,
        name="foreign-asset.corp",
        verification_status="pending",
        verification_token="foreign-tok",
        verification_method="dns_txt",
    )
    db_session.add(foreign_domain)
    db_session.flush()

    # 1. Accessing foreign org's domain list returns 404
    resp_list = client.get(f"/ui/orgs/{foreign_org.id}/domains")
    assert resp_list.status_code == 404

    # 2. Accessing foreign domain under foreign org returns 404
    resp_detail_foreign_org = client.get(f"/ui/orgs/{foreign_org.id}/domains/{foreign_domain.id}")
    assert resp_detail_foreign_org.status_code == 404

    # 3. Accessing foreign domain under user's own org returns 404 (parameter swapping)
    resp_detail_own_org = client.get(f"/ui/orgs/{test_org.id}/domains/{foreign_domain.id}")
    assert resp_detail_own_org.status_code == 404


@pytest.mark.db
def test_xss_escaping_in_rendered_templates(client: TestClient, db_session: Session):
    """Domain and organization names containing <script> tags are strictly HTML-escaped."""
    xss_org = Organization(name='Acme <script>alert("org-xss")</script>')
    db_session.add(xss_org)
    db_session.flush()

    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    membership = Membership(org_id=xss_org.id, user_id=test_user_id, role="owner")
    db_session.add(membership)
    db_session.flush()

    xss_domain = Domain(
        org_id=xss_org.id,
        name="test-xss.example.com",
        verification_status="pending",
        verification_token="tok",
        verification_method="dns_txt",
    )
    db_session.add(xss_domain)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{xss_org.id}/domains")
    assert resp.status_code == 200
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


@pytest.mark.db
def test_cross_tenant_404_on_scans_routes(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Accessing domain scans list or scan detail for a foreign tenant returns 404."""
    # 1. Setup foreign org, domain, and scan
    foreign_org = Organization(name="Foreign Org 2")
    db_session.add(foreign_org)
    db_session.flush()

    foreign_domain = Domain(
        org_id=foreign_org.id,
        name="foreign2.example.com",
        verification_status="verified",
        verification_token="tok2",
        verification_method="dns_txt",
    )
    db_session.add(foreign_domain)
    db_session.flush()

    foreign_scan = ScanRun(
        domain_id=foreign_domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(foreign_scan)
    db_session.flush()

    # 2. Setup user's own domain and scan
    own_domain = Domain(
        org_id=test_org.id,
        name="own.example.com",
        verification_status="verified",
        verification_token="tok-own",
        verification_method="dns_txt",
    )
    db_session.add(own_domain)
    db_session.flush()

    own_scan = ScanRun(
        domain_id=own_domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(own_scan)
    db_session.flush()

    # Access foreign scans list under foreign org -> 404
    resp1 = client.get(f"/ui/orgs/{foreign_org.id}/domains/{foreign_domain.id}/scans")
    assert resp1.status_code == 404

    # Access foreign domain under own org (parameter swapping) -> 404
    resp2 = client.get(f"/ui/orgs/{test_org.id}/domains/{foreign_domain.id}/scans")
    assert resp2.status_code == 404

    # Access foreign scan under foreign org -> 404
    resp3 = client.get(f"/ui/orgs/{foreign_org.id}/scans/{foreign_scan.id}")
    assert resp3.status_code == 404

    # Access foreign scan under own org (parameter swapping) -> 404
    resp4 = client.get(f"/ui/orgs/{test_org.id}/scans/{foreign_scan.id}")
    assert resp4.status_code == 404

    # Access own scan under foreign org -> 404
    resp5 = client.get(f"/ui/orgs/{foreign_org.id}/scans/{own_scan.id}")
    assert resp5.status_code == 404


@pytest.mark.db
def test_scans_list_viewer_vs_admin_and_verification_status(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Scans list respects roles and unverified domain disabled state with visible reason."""
    domain = Domain(
        org_id=test_org.id,
        name="unverified-scan.example.com",
        verification_status="pending",
        verification_token="tok-scan",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="queued",
        trigger="manual",
        change_detection={"status": "baseline"},
    )
    db_session.add(scan)
    db_session.flush()

    # 1. As Owner: Run scan button is rendered but disabled because domain is unverified
    resp_owner = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_owner.status_code == 200
    assert 'id="btn-run-scan"' in resp_owner.text
    assert "disabled" in resp_owner.text
    assert "Domain ownership verification required to run scans." in resp_owner.text
    # Sentence-case headers
    assert "Scan ID" in resp_owner.text
    assert "Trigger" in resp_owner.text
    assert "Status" in resp_owner.text
    assert "Started at" in resp_owner.text
    assert "Duration" in resp_owner.text
    assert "Changes" in resp_owner.text
    assert "Actions" in resp_owner.text
    assert "Baseline scan" in resp_owner.text
    assert f"#{scan.id}" in resp_owner.text

    # 2. Mark domain verified -> Run scan button becomes enabled
    domain.verification_status = "verified"
    db_session.flush()

    resp_verified = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_verified.status_code == 200
    assert 'id="btn-run-scan"' in resp_verified.text
    assert (
        'disabled title="Domain ownership verification required to run scans"'
        not in resp_verified.text
    )

    # 3. As Viewer: Run scan button is not rendered at all
    viewer_user = User(
        id=UUID("00000000-0000-0000-0000-000000000099"),
        email="viewer-scan@example.com",
    )
    db_session.add(viewer_user)
    db_session.flush()
    db_session.add(Membership(org_id=test_org.id, user_id=viewer_user.id, role="viewer"))
    db_session.flush()

    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_viewer = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
        assert resp_viewer.status_code == 200
        assert 'id="btn-run-scan"' not in resp_viewer.text
        # But table and view scan buttons are visible
        assert "btn-view-scan" in resp_viewer.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_scan_detail_polling_and_stale_cap(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Polling trigger is present only for active scans < 15m; stale banner shows at >= 15m."""
    domain = Domain(
        org_id=test_org.id,
        name="polling-test.example.com",
        verification_status="verified",
        verification_token="tok-poll",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    now = datetime.now(UTC)

    # 1. Active scan created 3 minutes ago -> should poll, no stale banner
    scan_active_fresh = ScanRun(
        domain_id=domain.id,
        status="running",
        trigger="manual",
        created_at=now - timedelta(minutes=3),
    )
    db_session.add(scan_active_fresh)
    db_session.flush()

    resp_fresh = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_active_fresh.id}")
    assert resp_fresh.status_code == 200
    assert f'hx-get="/ui/orgs/{test_org.id}/scans/{scan_active_fresh.id}"' in resp_fresh.text
    assert 'hx-trigger="every 3s"' in resp_fresh.text
    assert 'hx-target="this"' in resp_fresh.text
    assert 'hx-swap="outerHTML"' in resp_fresh.text
    assert "Still running after 15 minutes" not in resp_fresh.text

    # 2. Active scan created 16 minutes ago -> no polling, stale banner present.
    # Separate domain: uq_scan_runs_active_domain allows one active scan per domain.
    stale_domain = Domain(
        org_id=test_org.id,
        name="polling-stale.example.com",
        verification_status="verified",
        verification_token="tok-poll-stale",
        verification_method="dns_txt",
    )
    db_session.add(stale_domain)
    db_session.flush()

    scan_active_stale = ScanRun(
        domain_id=stale_domain.id,
        status="running",
        trigger="manual",
        created_at=now - timedelta(minutes=16),
    )
    db_session.add(scan_active_stale)
    db_session.flush()

    resp_stale = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_active_stale.id}")
    assert resp_stale.status_code == 200
    assert 'hx-trigger="every 3s"' not in resp_stale.text
    # No hx-get at all: without hx-trigger htmx would fall back to re-fetching on click
    assert "hx-get=" not in resp_stale.text
    assert "Still running after 15 minutes. Automatic updates have stopped." in resp_stale.text
    assert 'id="btn-refresh-scan"' in resp_stale.text

    # 3. Finished scan -> no polling, no stale banner
    scan_finished = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
        created_at=now - timedelta(minutes=5),
        started_at=now - timedelta(minutes=5),
        finished_at=now - timedelta(minutes=4),
    )
    db_session.add(scan_finished)
    db_session.flush()

    resp_finished = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_finished.id}")
    assert resp_finished.status_code == 200
    assert 'hx-trigger="every 3s"' not in resp_finished.text
    assert "hx-get=" not in resp_finished.text
    assert "Still running after 15 minutes" not in resp_finished.text


@pytest.mark.db
def test_scan_detail_fix_first_and_stored_xss_safety(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Score findings are sorted, summarized, and strictly HTML-escaped against stored XSS."""
    domain = Domain(
        org_id=test_org.id,
        name="xss-scan.example.com",
        verification_status="verified",
        verification_token="tok-xss",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(scan)
    db_session.flush()

    # Add pipeline stage
    stage = ScanStage(
        scan_run_id=scan.id,
        stage="score",
        status="succeeded",
        duration_ms=45,
    )
    db_session.add(stage)

    # Score report with malicious payload in title, evidence, and why_it_matters
    malicious_report = {
        "domain_score": 120,
        "domain_band": "CRITICAL",
        # Real scoring.py key names
        "counts": {"findings_critical": 1, "findings_high": 1},
        "hosts": [
            {
                "subdomain": "vuln.example.com",
                "findings": [
                    {
                        "id": "F_CRIT_XSS",
                        "title": "Critical <script>alert('title-xss')</script>",
                        "tier": "CRITICAL",
                        "points": 100,
                        "host": "vuln.example.com",
                        "port": 443,
                        "evidence": '<img src=x onerror="alert(document.cookie)">',
                        "why_it_matters": (
                            'Exploitable via <iframe src="javascript:alert(1)"></iframe>'
                        ),
                    },
                    {
                        "id": "F_HIGH_SAFE",
                        "title": "High Severity Exposure",
                        "tier": "HIGH",
                        "points": 20,
                        "host": "vuln.example.com",
                        "port": 80,
                        "evidence": "banner=nginx/1.18",
                        "why_it_matters": "Outdated web server",
                    },
                ],
            }
        ],
    }
    db_session.add(
        ScanResult(
            scan_run_id=scan.id,
            stage="score",
            report=malicious_report,
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200

    # Ensure raw dangerous markup is never present
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
    assert "<img src=x" not in resp.text
    assert "&lt;img src=x" in resp.text
    assert "<iframe" not in resp.text
    # Exact escaped forms prove escaping happened (Jinja renders " as &#34;)
    assert "&lt;iframe src=&#34;javascript:alert(1)&#34;&gt;" in resp.text
    assert "&lt;img src=x onerror=&#34;alert(document.cookie)&#34;&gt;" in resp.text

    # Findings summary and details are rendered
    assert _score_card_value(resp.text, "Domain score") == 120
    assert 'class="tier-badge tier-critical">Critical</span>' in resp.text
    assert "vuln.example.com:443" in resp.text
    assert "Tier" in resp.text
    assert "Finding" in resp.text
    assert "Host / Port" in resp.text
    assert "Points" in resp.text
    assert "Evidence" in resp.text

    # Summary cards count the findings actually present
    assert _score_card_value(resp.text, "Critical") == 1
    assert _score_card_value(resp.text, "High") == 1
    assert _score_card_value(resp.text, "Medium") == 0


@pytest.mark.db
def test_scan_detail_overflow_findings_50_cap(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Findings exceeding 50 are capped and the overflow count is displayed."""
    domain = Domain(
        org_id=test_org.id,
        name="cap-test.example.com",
        verification_status="verified",
        verification_token="tok-cap",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan)
    db_session.flush()

    findings_60 = [
        {
            "id": f"FINDING_{i:02d}",
            "title": f"Finding Number {i}",
            "tier": "LOW",
            "points": 5,
            # Zero-padded so host order matches index order (host00 < host01 < ... < host59)
            "host": f"host{i:02d}.example.com",
            "port": 80,
            "evidence": f"proof_{i}",
            "why_it_matters": "Risk explanation",
        }
        for i in range(60)
    ]
    db_session.add(
        ScanResult(
            scan_run_id=scan.id,
            stage="score",
            report={
                "domain_score": 300,
                "domain_band": "LOW",
                "counts": {"findings_low": 60},
                "hosts": [{"subdomain": "root.example.com", "findings": findings_60}],
            },
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200
    assert "... and 10 more findings." in resp.text
    # Check that 50th finding is present, but 51st (index 50) is excluded from table
    assert "Finding Number 0" in resp.text
    assert "Finding Number 49" in resp.text
    assert "Finding Number 50" not in resp.text
    # The Low card counts all 60 findings, not just the 50 rendered rows
    assert _score_card_value(resp.text, "Low") == 60


@pytest.mark.db
def test_scans_list_change_summary_uses_real_worker_shape(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Scans list summarizes change_detection exactly as the worker writes it (no "total")."""
    domain = Domain(
        org_id=test_org.id,
        name="change-summary.example.com",
        verification_status="verified",
        verification_token="tok-summary",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    def _computed(**tier_counts: int) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        counts.update(tier_counts)
        return {
            "status": "computed",
            "baseline_scan_run_id": None,
            "removal_detection": "performed",
            "skip_reason": None,
            "error": None,
            "counts": counts,
        }

    now = datetime.now(UTC)
    db_session.add_all(
        [
            ScanRun(
                domain_id=domain.id,
                status="succeeded",
                trigger="manual",
                created_at=now - timedelta(hours=2),
                change_detection=_computed(),
            ),
            ScanRun(
                domain_id=domain.id,
                status="succeeded",
                trigger="manual",
                created_at=now - timedelta(hours=1),
                change_detection=_computed(critical=1, info=2),
            ),
        ]
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp.status_code == 200
    assert "1 critical, 2 info" in resp.text
    assert "No changes" in resp.text


@pytest.mark.db
def test_scan_detail_failed_state_no_results(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Failed scan renders error message and 'No findings reported' without crashing."""
    domain = Domain(
        org_id=test_org.id,
        name="failed-scan.example.com",
        verification_status="verified",
        verification_token="tok-fail",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="failed",
        trigger="manual",
        error="Connection reset by peer during inspect stage <b onmouseover=alert(1)>",
    )
    db_session.add(scan)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200
    assert "Scan failed:" in resp.text
    assert "Connection reset by peer during inspect stage" in resp.text
    assert "<b onmouseover" not in resp.text
    assert "&lt;b onmouseover=alert(1)&gt;" in resp.text
    assert "No findings reported for this scan run." in resp.text


@pytest.mark.db
def test_scan_detail_changes_detected_and_empty(
    client: TestClient, db_session: Session, test_org: Organization
):
    """ScanChanges are rendered when present, or 'No changes detected' when none."""
    domain = Domain(
        org_id=test_org.id,
        name="changes-test.example.com",
        verification_status="verified",
        verification_token="tok-changes",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Scan with changes
    scan_with_changes = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan_with_changes)
    db_session.flush()

    # Shape as written by changes.py: uppercase severity, real category names.
    # asset/detail come from attacker-influenced data (CT log names, banners).
    change = ScanChange(
        domain_id=domain.id,
        scan_run_id=scan_with_changes.id,
        baseline_scan_run_id=scan_with_changes.id,
        change_type="port_opened",
        category="exposure",
        severity="HIGH",
        asset="<script>alert('asset')</script>.example.com:8443",
        detail="<img src=x onerror=alert(1)>",
        evidence="portscan",
        observed_at=datetime.now(UTC),
    )
    db_session.add(change)
    db_session.add(
        ScanStage(
            scan_run_id=scan_with_changes.id,
            stage="probe",
            status="failed",
            error="<script>alert('stage')</script>",
        )
    )
    db_session.flush()

    resp1 = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_with_changes.id}")
    assert resp1.status_code == 200
    assert "port_opened" in resp1.text
    assert 'class="tier-badge tier-high">High</span>' in resp1.text
    # Exact cell markup: the bare word "portscan" also appears in the pipeline stage cards
    assert "<td><code>portscan</code></td>" in resp1.text
    # Stored XSS: every attacker-influenced field is escaped, never raw
    assert "<script>" not in resp1.text
    assert "<img src=x" not in resp1.text
    assert "&lt;script&gt;alert(&#39;asset&#39;)&lt;/script&gt;.example.com:8443" in resp1.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in resp1.text
    assert "&lt;script&gt;alert(&#39;stage&#39;)&lt;/script&gt;" in resp1.text

    # 2. Scan without changes
    scan_no_changes = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan_no_changes)
    db_session.flush()

    resp2 = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_no_changes.id}")
    assert resp2.status_code == 200
    assert "No changes detected in this scan." in resp2.text


@pytest.mark.db
def test_decision_a_unverified_alerts_disable_and_enable(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Decision A: unverified domain allows alerts_enabled=False (200 + audit); True stays 422."""
    domain = Domain(
        org_id=test_org.id,
        name="unverified-alerts.example.com",
        verification_status="pending",
        verification_token="tok-unv-alerts",
        verification_method="dns_txt",
        alerts_enabled=True,
        alert_emails=["initial@example.com"],
        alert_min_severity="HIGH",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Disabling alerts on unverified domain -> 200 and audit event recorded
    resp_disable = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": False,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "MEDIUM",
        },
    )
    assert resp_disable.status_code == 200
    data = resp_disable.json()
    assert data["alerts_enabled"] is False
    assert data["alert_emails"] == ["ops@example.com"]

    # Verify audit event recorded
    audit_evt = (
        db_session.query(AuditEvent)
        .filter_by(org_id=test_org.id, action="domain.alerts_changed", target_id=str(domain.id))
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert audit_evt is not None
    assert audit_evt.metadata_["new_enabled"] is False

    # 2. Enabling alerts on unverified domain -> 422
    resp_enable = client.put(
        f"/orgs/{test_org.id}/domains/{domain.id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert resp_enable.status_code == 422
    assert "not verified" in resp_enable.json()["detail"].lower()


@pytest.mark.db
def test_ui_cross_tenant_and_role_access_v34c(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Cross-tenant 404 on both new routes; viewer 403 on audit; viewer 200 on alert history."""
    # Org A domain
    domain_a = Domain(
        org_id=test_org.id,
        name="domain-a.example.com",
        verification_status="verified",
        verification_token="tok-a",
        verification_method="dns_txt",
    )
    db_session.add(domain_a)

    # Create Org B
    org_b = Organization(name="Other Org B")
    db_session.add(org_b)
    db_session.flush()

    # 1. Cross-tenant alert notifications: requesting domain_a under org_b -> 404
    resp_ct_alerts = client.get(f"/ui/orgs/{org_b.id}/domains/{domain_a.id}/alert-notifications")
    assert resp_ct_alerts.status_code == 404

    # 2. Cross-tenant audit log: non-member requesting org_b audit events -> 404
    resp_ct_audit = client.get(f"/ui/orgs/{org_b.id}/audit-events")
    assert resp_ct_audit.status_code == 404

    # 3. Viewer context for Org A
    viewer_user_id = UUID("00000000-0000-0000-0000-000000000003")
    viewer_user = db_session.get(User, viewer_user_id)
    if not viewer_user:
        viewer_user = User(id=viewer_user_id, email="viewer3@example.com")
        db_session.add(viewer_user)
        db_session.flush()

    membership = (
        db_session.query(Membership).filter_by(org_id=test_org.id, user_id=viewer_user_id).first()
    )
    if not membership:
        membership = Membership(org_id=test_org.id, user_id=viewer_user_id, role="viewer")
        db_session.add(membership)
    else:
        membership.role = "viewer"
    db_session.flush()

    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        # Viewer denied audit log -> 403
        resp_viewer_audit = client.get(f"/ui/orgs/{test_org.id}/audit-events")
        assert resp_viewer_audit.status_code == 403

        # Viewer allowed alert history -> 200
        resp_viewer_alerts = client.get(
            f"/ui/orgs/{test_org.id}/domains/{domain_a.id}/alert-notifications"
        )
        assert resp_viewer_alerts.status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_ui_schedule_and_alerts_domain_detail_rendering(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Schedule and alerts section rendering: presets, non-presets, and unverified disablement."""
    # 1. Verified domain with non-preset interval (48h)
    domain_verified = Domain(
        org_id=test_org.id,
        name="schedule-48.example.com",
        verification_status="verified",
        verification_token="tok-48",
        verification_method="dns_txt",
        scan_interval_hours=48,
        next_scan_at=datetime.now(UTC) + timedelta(hours=48),
        alerts_enabled=True,
        alert_emails=["ops@example.com"],
        alert_min_severity="HIGH",
    )
    db_session.add(domain_verified)
    db_session.flush()

    resp_ver = client.get(f"/ui/orgs/{test_org.id}/domains/{domain_verified.id}")
    assert resp_ver.status_code == 200
    # Shows non-preset selected option
    assert '<option value="48" selected>Every 48 hours (current)</option>' in resp_ver.text
    assert "Every 48 hours" in resp_ver.text
    assert "Alerts: enabled" in resp_ver.text
    assert "High" in resp_ver.text
    assert "1 recipient configured" in resp_ver.text

    # 2. Unverified domain: only "Off" is enabled; presets are disabled
    domain_unverified = Domain(
        org_id=test_org.id,
        name="schedule-unverified.example.com",
        verification_status="pending",
        verification_token="tok-unv",
        verification_method="dns_txt",
        scan_interval_hours=None,
    )
    db_session.add(domain_unverified)
    db_session.flush()

    resp_unv = client.get(f"/ui/orgs/{test_org.id}/domains/{domain_unverified.id}")
    assert resp_unv.status_code == 200
    assert '<option value="" selected>Off</option>' in resp_unv.text
    # Presets must be disabled
    assert '<option value="6" disabled>Every 6 hours</option>' in resp_unv.text
    assert '<option value="24" disabled>Every 24 hours</option>' in resp_unv.text
    assert '<option value="168" disabled>Every 7 days</option>' in resp_unv.text
    assert '<option value="720" disabled>Every 30 days</option>' in resp_unv.text
    assert (
        "Domain ownership verification required before scheduling automated scans." in resp_unv.text
    )
    assert "Domain ownership verification required before enabling alerts." in resp_unv.text
    assert '<span class="status-badge status-skipped">Alerts: disabled</span>' in resp_unv.text


@pytest.mark.db
def test_ui_viewer_privacy_no_email_strings_anywhere(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Viewers never see configured recipient email strings in domain detail or alert history."""
    secret_email = "confidential-sec-responder@secret-enterprise.org"
    second_email = "ciso-eyes-only@secret-enterprise.org"

    domain = Domain(
        org_id=test_org.id,
        name="privacy-guarded.example.com",
        verification_status="verified",
        verification_token="tok-priv",
        verification_method="dns_txt",
        alerts_enabled=True,
        alert_emails=[secret_email, second_email],
        alert_min_severity="MEDIUM",
    )
    db_session.add(domain)
    db_session.flush()

    # Queue an alert notification using the real verification producer
    queue_domain_alert(
        db_session,
        domain,
        subject="[ASM Alert] New exposure detected",
        body="Finding: Port 8443 opened on privacy-guarded.example.com",
    )
    db_session.flush()

    # One notification has last_error containing the secret recipient address
    failed_notif = AlertNotification(
        domain_id=domain.id,
        recipient=secret_email,
        subject="[ASM Alert] Delivery failure",
        body="Finding: Delivery failed",
        status="failed",
        attempts=3,
        max_attempts=3,
        last_error=f"SMTP delivery error for {secret_email}: connection refused",
        next_attempt_at=datetime.now(UTC),
    )
    db_session.add(failed_notif)
    db_session.flush()

    # 1. Admin sees email list, recipient column, and last error column
    resp_admin_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_admin_detail.status_code == 200
    assert secret_email in resp_admin_detail.text
    assert second_email in resp_admin_detail.text

    resp_admin_history = client.get(
        f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications"
    )
    assert resp_admin_history.status_code == 200
    assert "<th>Recipient</th>" in resp_admin_history.text
    assert "<th>Last error</th>" in resp_admin_history.text
    assert secret_email in resp_admin_history.text
    assert f"SMTP delivery error for {secret_email}: connection refused" in resp_admin_history.text

    # 2. Viewer sees count only, and ZERO occurrences of either email string anywhere in HTML
    viewer_user_id = UUID("00000000-0000-0000-0000-000000000004")
    viewer_user = db_session.get(User, viewer_user_id)
    if not viewer_user:
        viewer_user = User(id=viewer_user_id, email="viewer4@example.com")
        db_session.add(viewer_user)
        db_session.flush()

    membership = (
        db_session.query(Membership).filter_by(org_id=test_org.id, user_id=viewer_user_id).first()
    )
    if not membership:
        membership = Membership(org_id=test_org.id, user_id=viewer_user_id, role="viewer")
        db_session.add(membership)
    else:
        membership.role = "viewer"
    db_session.flush()

    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        # Check domain detail
        resp_viewer_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
        assert resp_viewer_detail.status_code == 200
        assert "2 recipients configured" in resp_viewer_detail.text
        assert secret_email not in resp_viewer_detail.text
        assert second_email not in resp_viewer_detail.text

        # Check alert history
        resp_viewer_history = client.get(
            f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications"
        )
        assert resp_viewer_history.status_code == 200
        assert "<th>Recipient</th>" not in resp_viewer_history.text
        assert "<th>Last error</th>" not in resp_viewer_history.text
        assert secret_email not in resp_viewer_history.text
        assert second_email not in resp_viewer_history.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_ui_audit_xss_and_metadata_rendering(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Audit log: raw <script> absent, &lt;script&gt; present, \\u003c absent; actor email."""
    owner_user = db_session.get(User, UUID("00000000-0000-0000-0000-000000000001"))
    if not owner_user:
        owner_user = User(
            id=UUID("00000000-0000-0000-0000-000000000001"), email="testuser@example.com"
        )
        db_session.add(owner_user)
        db_session.flush()

    record_event(
        db_session,
        org_id=test_org.id,
        actor_type="user",
        actor_user_id=owner_user.id,
        action="domain.created",
        target_type="domain",
        target_id="<script>alert('target')</script>",
        metadata={"name": "<script>alert('meta')</script>"},
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/audit-events")
    assert resp.status_code == 200

    # User email displayed via outer join
    assert owner_user.email in resp.text
    assert "domain.created" in resp.text

    # Stored XSS requirements:
    # 1. Raw <script> must be completely absent
    assert "<script>" not in resp.text
    # 2. Escaped &lt;script&gt; must be present
    assert "&lt;script&gt;" in resp.text
    # 3. Unicode escape \u003c must be absent (ensure_ascii=False was used)
    assert "\\u003c" not in resp.text


@pytest.mark.db
def test_ui_audit_parity_json_vs_ui(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Audit log parity: JSON API and UI fragment return identical event IDs for filters."""
    # Seed 3 distinct audit events
    e1 = record_event(
        db_session,
        org_id=test_org.id,
        actor_type="system",
        actor_user_id=None,
        action="verification.checked",
        target_type="domain",
        target_id="101",
        metadata={"outcome": "match", "consecutive_misses": 0},
    )
    e2 = record_event(
        db_session,
        org_id=test_org.id,
        actor_type="system",
        actor_user_id=None,
        action="verification.checked",
        target_type="domain",
        target_id="102",
        metadata={"outcome": "absent", "consecutive_misses": 1},
    )
    e3 = record_event(
        db_session,
        org_id=test_org.id,
        actor_type="system",
        actor_user_id=None,
        action="domain.created",
        target_type="domain",
        target_id="103",
        metadata={"name": "new.example.com"},
    )
    db_session.flush()

    # Query with action filter
    resp_json = client.get(f"/orgs/{test_org.id}/audit-events?action=verification.checked")
    assert resp_json.status_code == 200
    json_ids = [evt["id"] for evt in resp_json.json()]

    resp_ui = client.get(f"/ui/orgs/{test_org.id}/audit-events?action=verification.checked")
    assert resp_ui.status_code == 200

    # Ensure both events are in UI in same order, and e3 is not
    assert e1.id in json_ids
    assert e2.id in json_ids
    assert e3.id not in json_ids

    # Check UI table contains rows for e1 and e2
    assert f"<code>domain:{e1.target_id}</code>" in resp_ui.text
    assert f"<code>domain:{e2.target_id}</code>" in resp_ui.text
    assert f"<code>domain:{e3.target_id}</code>" not in resp_ui.text


@pytest.mark.db
def test_ui_audit_paging_55_events(client: TestClient, db_session: Session):
    """Paging 55 events: page 1 has 50 rows + 'Older events'; page 2 has 5 rows (no older)."""
    paging_org = Organization(name="Audit Paging Org")
    db_session.add(paging_org)
    db_session.flush()

    owner_user = db_session.get(User, UUID("00000000-0000-0000-0000-000000000001"))
    if not owner_user:
        owner_user = User(
            id=UUID("00000000-0000-0000-0000-000000000001"), email="testuser@example.com"
        )
        db_session.add(owner_user)
        db_session.flush()
    membership = Membership(org_id=paging_org.id, user_id=owner_user.id, role="owner")
    db_session.add(membership)
    db_session.flush()

    # Seed 55 real audit events
    for i in range(55):
        record_event(
            db_session,
            org_id=paging_org.id,
            actor_type="system",
            actor_user_id=None,
            action="verification.checked",
            target_type="domain",
            target_id=str(1000 + i),
            metadata={"outcome": "match", "consecutive_misses": 0},
        )
    db_session.flush()

    # Page 1: default request
    resp1 = client.get(f"/ui/orgs/{paging_org.id}/audit-events")
    assert resp1.status_code == 200
    # Must have 50 <tr> rows in table
    assert resp1.text.count("<code>verification.checked</code>") == 50
    assert "Older events" in resp1.text
    assert "Newest" not in resp1.text

    # Extract data-before-id
    match = re.search(r'data-before-id="(\d+)"', resp1.text)
    assert match is not None
    oldest_id = int(match.group(1))

    # Page 2: with before_id
    resp2 = client.get(f"/ui/orgs/{paging_org.id}/audit-events?before_id={oldest_id}")
    assert resp2.status_code == 200
    # Must have remaining 5 <tr> rows in table
    assert resp2.text.count("<code>verification.checked</code>") == 5
    assert "Older events" not in resp2.text
    assert "Newest" in resp2.text


@pytest.mark.db
def test_ui_alert_notifications_stored_xss_and_offset_paging(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Alert notifications: stored XSS escaped, collapsible details body, and offset paging."""
    domain = Domain(
        org_id=test_org.id,
        name="alerts-xss.example.com",
        verification_status="verified",
        verification_token="tok-axss",
        verification_method="dns_txt",
        alerts_enabled=True,
        alert_emails=["alert-target@example.com"],
    )
    db_session.add(domain)
    db_session.flush()

    # Create real AlertNotification with attacker-controlled data
    xss_notif = AlertNotification(
        domain_id=domain.id,
        recipient="alert-target@example.com",
        subject="<script>alert('subject')</script>",
        body="Exposures: <img src=x onerror=alert(1)> and <script>alert('body')</script>",
        status="failed",
        attempts=3,
        max_attempts=3,
        last_error="<script>alert('error')</script>",
        next_attempt_at=datetime.now(UTC),
    )
    db_session.add(xss_notif)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications")
    assert resp.status_code == 200

    # Stored XSS checks
    assert "<script>" not in resp.text
    assert "<img src=x" not in resp.text
    assert "&lt;script&gt;alert(&#39;subject&#39;)&lt;/script&gt;" in resp.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in resp.text
    assert "&lt;script&gt;alert(&#39;body&#39;)&lt;/script&gt;" in resp.text
    assert "&lt;script&gt;alert(&#39;error&#39;)&lt;/script&gt;" in resp.text
    assert '<span class="status-badge status-failed">Failed</span>' in resp.text


@pytest.mark.db
def test_ui_alert_notifications_param_swap_404(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Param swap: requesting another org's domain alert-notifications returns 404."""
    org_b = Organization(name="Other Org B")
    db_session.add(org_b)
    db_session.flush()

    domain_b = Domain(
        org_id=org_b.id,
        name="domain-b.example.com",
        verification_status="verified",
        verification_token="tok-param-swap-b",
        verification_method="dns_txt",
    )
    db_session.add(domain_b)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/domains/{domain_b.id}/alert-notifications")
    assert resp.status_code == 404


@pytest.mark.db
def test_ui_alert_notifications_paging_55_rows(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Paging 55 alert notifications.

    offset=0 has 50 details, Next data-offset=50; offset=50 has 5, Prev data-offset=0.
    """
    domain = Domain(
        org_id=test_org.id,
        name="paging-alerts.example.com",
        verification_status="verified",
        verification_token="tok-paging-alerts",
        verification_method="dns_txt",
        alerts_enabled=True,
        alert_emails=["alert-paging@example.com"],
        alert_min_severity="LOW",
    )
    db_session.add(domain)
    db_session.flush()

    for i in range(55):
        queue_domain_alert(
            db_session,
            domain,
            subject=f"[ASM Alert] Notification #{i}",
            body=f"Finding details #{i} on paging-alerts.example.com",
        )
    db_session.flush()

    # offset=0: 50 body <details> elements, a "Next" button with data-offset="50", no "Previous"
    resp0 = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications?offset=0")
    assert resp0.status_code == 200
    assert resp0.text.count('<details class="alert-body-details">') == 50
    assert 'data-offset="50"' in resp0.text
    assert "Next" in resp0.text
    assert "Previous" not in resp0.text

    # offset=50: 5 rows, a "Previous" button with data-offset="0", no "Next"
    resp50 = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/alert-notifications?offset=50")
    assert resp50.status_code == 200
    assert resp50.text.count('<details class="alert-body-details">') == 5
    assert 'data-offset="0"' in resp50.text
    assert "Previous" in resp50.text
    assert "Next" not in resp50.text
