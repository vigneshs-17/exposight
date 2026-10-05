"""Tests for SMTP alert delivery transport security (v3.6b A5). smtplib is mocked."""

import ssl
from unittest.mock import MagicMock, patch

import pytest

from asm.alerts.delivery import SMTPConfigError, send_smtp_email

BASE = {
    "host": "smtp.example.com",
    "from_addr": "alerts@example.com",
    "to_addr": "owner@example.com",
    "subject": "Exposight alert",
    "body": "body",
}


def _send(**kwargs):
    """Call send_smtp_email with smtplib.SMTP and SMTP_SSL mocked; return both mocks."""
    with (
        patch("asm.alerts.delivery.smtplib.SMTP") as smtp_cls,
        patch("asm.alerts.delivery.smtplib.SMTP_SSL") as smtps_cls,
    ):
        for cls in (smtp_cls, smtps_cls):
            cls.return_value.__enter__.return_value = MagicMock()
        send_smtp_email(**{**BASE, **kwargs})
    return smtp_cls, smtps_cls


def test_credentials_without_tls_are_refused_and_nothing_connects():
    with (
        patch("asm.alerts.delivery.smtplib.SMTP") as smtp_cls,
        patch("asm.alerts.delivery.smtplib.SMTP_SSL") as smtps_cls,
    ):
        with pytest.raises(SMTPConfigError, match="without TLS"):
            send_smtp_email(**BASE, port=587, username="user", password="pw")
    smtp_cls.assert_not_called()
    smtps_cls.assert_not_called()


def test_password_alone_without_tls_is_refused():
    with patch("asm.alerts.delivery.smtplib.SMTP") as smtp_cls:
        with pytest.raises(SMTPConfigError):
            send_smtp_email(**BASE, port=587, password="pw")
    smtp_cls.assert_not_called()


def test_refusal_message_contains_no_secret():
    with pytest.raises(SMTPConfigError) as excinfo:
        send_smtp_email(**BASE, port=587, username="user", password="Sup3rSecret")
    assert "Sup3rSecret" not in str(excinfo.value)


def test_both_tls_modes_is_a_config_error():
    with pytest.raises(SMTPConfigError, match="cannot both"):
        send_smtp_email(**BASE, port=465, use_ssl=True, use_starttls=True)


def test_starttls_with_credentials_logs_in_after_verified_starttls():
    smtp_cls, smtps_cls = _send(port=587, username="user", password="pw", use_starttls=True)
    server = smtp_cls.return_value.__enter__.return_value
    context = server.starttls.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    server.login.assert_called_once_with("user", "pw")
    smtps_cls.assert_not_called()


def test_smtps_uses_verifying_context_and_never_starttls():
    smtp_cls, smtps_cls = _send(port=465, username="user", password="pw", use_ssl=True)
    smtp_cls.assert_not_called()
    context = smtps_cls.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert smtps_cls.call_args.kwargs["port"] == 465
    server = smtps_cls.return_value.__enter__.return_value
    server.starttls.assert_not_called()
    server.login.assert_called_once_with("user", "pw")
    server.send_message.assert_called_once()


def test_plain_smtp_without_credentials_still_allowed_for_local_mailpit():
    smtp_cls, _ = _send(port=1025)
    server = smtp_cls.return_value.__enter__.return_value
    server.login.assert_not_called()
    server.send_message.assert_called_once()


def test_worker_reads_smtp_ssl_from_environment(monkeypatch):
    from asm.worker.worker import ASMWorker

    monkeypatch.setenv("SMTP_SSL", "true")
    worker = ASMWorker(engine=MagicMock())
    assert worker.smtp_ssl is True
    monkeypatch.setenv("SMTP_SSL", "false")
    assert ASMWorker(engine=MagicMock()).smtp_ssl is False
