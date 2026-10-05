"""SMTP delivery client for alert notifications."""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class SMTPConfigError(ValueError):
    """Raised when the SMTP settings are unsafe or contradictory; nothing is sent."""


def validate_email_address_header(addr: str) -> str:
    """Ensure email address has no CR or LF characters to prevent header injection."""
    if "\r" in addr or "\n" in addr:
        raise ValueError("Email address contains carriage return or line feed characters")
    return addr.strip()


def send_smtp_email(
    host: str,
    port: int,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    username: str | None = None,
    password: str | None = None,
    use_starttls: bool = False,
    timeout: float = 10.0,
    use_ssl: bool = False,
) -> None:
    """Send a single plain-text alert email via SMTP.

    Args:
        host: SMTP server hostname.
        port: SMTP server port.
        from_addr: Sender email address.
        to_addr: Recipient email address.
        subject: Email subject line.
        body: Plain-text email body.
        username: Optional SMTP auth username.
        password: Optional SMTP auth password (never logged).
        use_starttls: Whether to upgrade connection via STARTTLS.
        timeout: Socket timeout in seconds.
        use_ssl: Whether to connect with implicit TLS (SMTPS, usually port 465).

    Raises:
        SMTPConfigError: Credentials are set but neither TLS mode is enabled
            (they would be sent in clear text), or both TLS modes are enabled.
    """
    if use_ssl and use_starttls:
        raise SMTPConfigError("SMTP_SSL and SMTP_STARTTLS cannot both be enabled")
    if (username or password) and not (use_ssl or use_starttls):
        raise SMTPConfigError(
            "Refusing to send SMTP credentials without TLS: enable SMTP_STARTTLS or SMTP_SSL"
        )

    clean_from = validate_email_address_header(from_addr)
    clean_to = validate_email_address_header(to_addr)
    clean_subject = re.sub(r"[\r\n]", "", subject).strip()

    msg = EmailMessage()
    msg["Subject"] = clean_subject
    msg["From"] = clean_from
    msg["To"] = clean_to
    msg.set_content(body)

    if use_ssl:
        # Implicit TLS: the certificate and hostname are verified before any SMTP command.
        smtp_client = smtplib.SMTP_SSL(
            host=host, port=port, timeout=timeout, context=ssl.create_default_context()
        )
    else:
        smtp_client = smtplib.SMTP(host=host, port=port, timeout=timeout)

    with smtp_client as server:
        if use_starttls:
            # Verify the server certificate and hostname; smtplib's default context does not.
            server.starttls(context=ssl.create_default_context())
        if username and password:
            server.login(username, password)
        server.send_message(msg)
