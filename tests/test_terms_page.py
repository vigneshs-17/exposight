"""v3.6b A8: public Terms & acceptable-use page."""

import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from asm.api.deps import reset_auth_dependencies
from asm.api.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV = {"SUPABASE_URL": "https://testproj.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "anon_key_1"}


def _get(path: str):
    with patch.dict(os.environ, ENV):
        reset_auth_dependencies()
        with TestClient(app) as client:
            return client.get(path)


def test_terms_page_served_with_strict_csp_and_no_auth():
    resp = _get("/terms")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_terms_page_states_acceptable_use_rules():
    html = _get("/terms").text
    assert "Only scan what you own or are authorised to test" in html
    assert "_asm-verify.&lt;your-domain&gt;" in html  # autoescaped, not raw markup
    assert "<script" not in html
    assert "style=" not in html
    assert " on" + "click=" not in html


def test_landing_footer_links_to_terms():
    html = _get("/").text
    assert 'href="/terms"' in html


def test_terms_states_operator_override_and_lapse_timing():
    html = _get("/terms").text
    assert "verify a domain manually for a limited period (1 to 90 days)" in html
    assert "after two definite misses in a row, so about a day after the record is removed" in html
    assert "inconclusive DNS lookup does not count as a miss" in html
    assert "Scanning stops when the record is removed" not in html


def test_terms_describes_suspension_as_implemented():
    """v3.6c B-4: suspension now exists; the page must describe exactly what it does."""
    html = _get("/terms").text
    assert "revoke its verification, which blocks further scans" in html
    assert "The operator can also suspend an account." in html
    assert 'every signed-in request is refused with "Account suspended"' in html
    assert "where every owner is suspended, scan schedules are turned off" in html
    assert "schedules stay off until an owner turns them on again" in html
    assert "reason for a suspension is not shown to the account" in html
    assert "if the account is suspended, when and why" in html
    assert "may be suspended" not in html  # no vague, unimplemented threat


def test_terms_lists_everything_stored():
    html = _get("/terms").text
    for fragment in (
        "Invites: the invited email address",
        "hash of the invite token (never the token itself)",
        "when you were last seen",
        "Alert notifications: recipient, subject, body, delivery status",
        "the last delivery error",
        "mask email addresses, tokens and other secrets in their logs",
        "database server's own error log can still contain values",
    ):
        assert fragment in html, fragment


def test_terms_describes_limits_and_retention_truthfully():
    html = _get("/terms").text
    assert "<code>429 Too many requests</code>" in html
    assert "emails over that limit are delayed" in html
    assert "returns an error that says which limit was reached" not in html
    assert "There is no automatic purge yet" not in html  # B-5 added one


def test_terms_describes_deletion_and_retention_as_implemented():
    """v3.6c B-5: each sentence matches routes_orgs.py and retention.py."""
    from datetime import timedelta

    from asm import retention

    html = _get("/terms").text
    for fragment in (
        "You can delete your own account with the API (<code>DELETE /me</code>)",
        "It is refused while you are the only owner of an organisation",
        "A suspended account cannot delete itself: its deletion requests go to the operator",
        "It is refused while one of its scans is running",
        "Your sign-in provider account is not deleted with it",
        "a new, empty Exposight account is created",
        "An owner can delete an organisation with the API",
        "The organisation's audit log is kept, under the name <code>deleted-org-&lt;id&gt;</code>",
        "An automatic purge exists, but it is off unless the operator turns it on.",
        "finished scans older than 180 days",
        "sent or failed alert notifications older than 90 days",
        "invites 30 days after they were accepted, revoked or expired",
        "Audit log entries are never purged.",
    ):
        assert fragment in html, fragment
    assert retention.SCAN_RETENTION == timedelta(days=180)
    assert retention.NOTIFICATION_RETENTION == timedelta(days=90)
    assert retention.INVITE_RETENTION == timedelta(days=30)


def test_terms_routes_security_reports_privately():
    html = _get("/terms").text
    assert "https://github.com/vigneshs-17/exposight/security/advisories/new" in html
    assert "never in a public issue" in html
    assert "mailto:" not in html


def test_terms_limit_messages_match_the_code():
    """The page quotes the 429 detail; keep it identical to what the limiter sends."""
    from asm.ratelimit import too_many_requests

    assert too_many_requests(1).detail == "Too many requests"


def test_security_md_points_to_private_reporting():
    text = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "https://github.com/vigneshs-17/exposight/security/advisories/new" in text
    assert "Do not open a public issue" in text
    assert "@" not in text  # no personal email address published
