"""v3.6b B-1: emails and secrets never reach logs (app loggers and uvicorn's access log)."""

import io
import logging
import smtplib
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from sqlalchemy.orm import Session
from uvicorn.logging import AccessFormatter

from asm.api.main import app
from asm.db.models import AlertNotification, Domain, Organization
from asm.logredact import install_log_redaction, redact
from asm.worker.worker import ASMWorker

FAKE_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"


@pytest.fixture(autouse=True)
def _redaction_installed():
    install_log_redaction()


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("delivery failed for owner@example.com", "owner@example.com"),
        ("550 <first.last+tag@sub.example.co.uk> rejected", "first.last+tag@sub.example.co.uk"),
        ("GET /app?token=abc123SECRET&x=1", "abc123SECRET"),
        ("GET /cb?code=pkce-code-123", "pkce-code-123"),
        ("GET /x?access_token=tok-AAA;y", "tok-AAA"),
        (f"bearer {FAKE_JWT} seen", FAKE_JWT),
    ],
)
def test_redact_masks_emails_secret_params_and_jwts(raw, secret):
    assert secret not in redact(raw)


def test_redact_keeps_ordinary_text():
    line = 'GET /orgs/1/domains?limit=20&status=queued HTTP/1.1 200 api.example.com 203.0.113.9'
    assert redact(line) == line


def test_app_log_record_args_and_traceback_are_redacted(caplog):
    logger = logging.getLogger("asm.test.redaction")
    with caplog.at_level(logging.INFO, logger="asm.test.redaction"):
        logger.info("user %s joined with %d roles", "alice@example.com", 2)
        try:
            raise smtplib.SMTPRecipientsRefused({"bob@example.com": (550, b"no such user")})
        except smtplib.SMTPException:
            logger.exception("send failed")
    text = caplog.text + "".join(r.exc_text or "" for r in caplog.records)
    assert "alice@example.com" not in text
    assert "bob@example.com" not in text
    assert "user [email] joined with 2 roles" in caplog.text


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_real_uvicorn_access_log_line_never_contains_tokens_or_emails():
    """R1: a request line as uvicorn really logs it must not contain secrets."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s'))
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.addHandler(handler)
    access_logger.setLevel(logging.INFO)

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=True)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started
        url = (
            f"http://127.0.0.1:{port}/terms?token=INVITE-SECRET-123&code=PKCE-456"
            f"&email=victim@example.com&jwt={FAKE_JWT}"
        )
        assert httpx.get(url, timeout=5).status_code == 200
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        access_logger.removeHandler(handler)

    logged = stream.getvalue()
    assert "/terms?" in logged  # the request line really was logged
    for secret in ("INVITE-SECRET-123", "PKCE-456", "victim@example.com", FAKE_JWT):
        assert secret not in logged, logged


def test_invite_token_is_never_read_from_the_url(client):
    """Invite tokens travel only in the POST body, so they never appear in a request line."""
    assert client.get("/invites/accept?token=x" * 1).status_code == 405
    resp = client.post("/invites/accept?token=abcdefghijklmnopqrstuvwxyz")
    assert resp.status_code == 422  # body required; the query parameter is ignored


@pytest.mark.db
def test_worker_delivery_failure_log_has_no_recipient(db_engine, clean_db, caplog):
    with Session(db_engine) as session:
        org = Organization(name="Log Org")
        session.add(org)
        session.flush()
        domain = Domain(org_id=org.id, name="log-redact.example.com")
        session.add(domain)
        session.flush()
        session.add(
            AlertNotification(
                domain_id=domain.id,
                recipient="secret.person@example.com",
                subject="s",
                body="b",
                status="pending",
                next_attempt_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )
        session.commit()

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    refused = smtplib.SMTPRecipientsRefused(
        {"secret.person@example.com": (550, b"5.1.1 <secret.person@example.com> unknown")}
    )
    with caplog.at_level(logging.WARNING), patch(
        "asm.worker.worker.send_smtp_email", side_effect=refused
    ):
        worker.deliver_pending_alerts()

    failure_lines = [r.getMessage() for r in caplog.records if "delivery failed" in r.getMessage()]
    assert failure_lines, caplog.text
    assert all("secret.person" not in line for line in failure_lines)
    assert "recipient=" not in caplog.text
