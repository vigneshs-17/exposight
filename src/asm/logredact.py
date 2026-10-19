"""Redact email addresses and secrets from every log record (v3.6b B-1).

Installed once per process (API, worker, admin CLI) with install_log_redaction().
It wraps the logging record factory, so it covers every logger, including
uvicorn's access log, whatever handlers or formatters are configured later.

Redacted:
- email addresses -> [email]
- secret-looking URL query parameters (token, code, access_token, ...) -> [redacted]
- JWT-shaped strings (three base64url parts starting with eyJ) -> [jwt]
- the password in a connection URL, JSON "access_token"/"password"-style values, and
  password:/password=/token= pairs -> [redacted] (IC-1, F7)

Message arguments are redacted one by one and keep their position, because
uvicorn's AccessFormatter unpacks record.args as a tuple.
"""

import logging
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_QUERY_RE = re.compile(
    r"([?&;](?:token|token_hash|code|access_token|refresh_token|id_token|apikey|api_key|key"
    r"|password|secret)=)[^&;#\s\"']*",
    re.IGNORECASE,
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# IC-1 (F7): the password in a connection URL (postgresql+psycopg://user:password@host).
URL_PASSWORD_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+(@)")
# JSON-style "access_token": "value" (also refresh/id tokens, password, secret).
JSON_SECRET_RE = re.compile(
    r'("(?:access_token|refresh_token|id_token|password|secret)"\s*:\s*")[^"]*(")',
    re.IGNORECASE,
)
# password: value, password=value, SMTP_PASSWORD=value, token=value. A value starting with
# ':' (an SQL placeholder) or '%' (a log argument not yet formatted) is left alone.
KEY_VALUE_SECRET_RE = re.compile(
    r"(\b(?:[A-Za-z0-9]+_)*(?:password|passwd|secret|token)\b\s*[:=]\s*)(?![:%]|\[redacted\])"
    r"[^\s&;,\"']+",
    re.IGNORECASE,
)

_installed = False


def redact(text: str) -> str:
    """Return text with emails, secret query parameters and JWTs masked."""
    text = JWT_RE.sub("[jwt]", text)
    text = URL_PASSWORD_RE.sub(r"\1[redacted]\2", text)
    text = JSON_SECRET_RE.sub(r"\1[redacted]\2", text)
    text = SECRET_QUERY_RE.sub(r"\1[redacted]", text)
    text = KEY_VALUE_SECRET_RE.sub(r"\1[redacted]", text)
    return EMAIL_RE.sub("[email]", text)


def _redact_arg(arg: object) -> object:
    """Redact strings and exceptions; leave numbers and other types unchanged."""
    if isinstance(arg, str):
        return redact(arg)
    if isinstance(arg, BaseException):
        return redact(str(arg))
    return arg


def redact_record(record: logging.LogRecord) -> logging.LogRecord:
    """Redact a log record in place and return it."""
    if isinstance(record.msg, str):
        record.msg = redact(record.msg)
    if isinstance(record.args, tuple):
        record.args = tuple(_redact_arg(a) for a in record.args)
    elif isinstance(record.args, dict):
        record.args = {k: _redact_arg(v) for k, v in record.args.items()}
    if record.exc_info and not record.exc_text:
        # Pre-render the traceback so its exception messages are redacted too;
        # formatters reuse exc_text instead of formatting the traceback again.
        record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
    return record


def install_log_redaction() -> None:
    """Make every log record created from now on pass through redact_record (idempotent)."""
    global _installed
    if _installed:
        return
    previous_factory = logging.getLogRecordFactory()

    def factory(*args, **kwargs) -> logging.LogRecord:
        return redact_record(previous_factory(*args, **kwargs))

    logging.setLogRecordFactory(factory)
    _installed = True
