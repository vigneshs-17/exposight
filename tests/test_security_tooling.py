"""Phase G: security-scanner hygiene.

Every bandit suppression in src/ must name its test ID and carry a written reason, and
the former silent ``except: pass`` blocks (bandit B110) must now log instead.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

from asm.portscan import scan_single_port
from asm.tls_inspect import parse_cert_dict

SRC = Path(__file__).resolve().parent.parent / "src"

# "code  # reason  # nosec B123" (reason on the line), or "code  # nosec B123" right under
# a comment block that says "Bandit B123 accepted: <reason>".
INLINE = re.compile(r"#\s*(?P<reason>[^#]*\w[^#]*?)\s+#\s*nosec\s+(?P<id>B\d{3})\s*$")
BARE = re.compile(r"#\s*nosec\s+(?P<id>B\d{3})\s*$")


def test_every_nosec_names_a_test_id_and_gives_a_reason():
    found = 0
    for path in sorted(SRC.rglob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "nosec" not in line:
                continue
            found += 1
            where = f"{path.relative_to(SRC)}:{i + 1}"
            inline, bare = INLINE.search(line), BARE.search(line)
            assert inline or bare, f"{where}: nosec without a B### test ID: {line.strip()}"
            if inline and len(inline["reason"].strip()) >= 10:
                continue
            test_id = bare["id"]
            above = "\n".join(lines[max(0, i - 6) : i])
            assert f"Bandit {test_id} accepted:" in above, (
                f"{where}: '# nosec {test_id}' needs a reason on the line or a "
                f"'Bandit {test_id} accepted: ...' comment just above"
            )
    assert found >= 9  # the accepted findings listed in STATUS.md "Phase G plan"


def test_malformed_certificate_dates_are_logged_not_silently_dropped(caplog):
    cert = {"notBefore": "not a date", "notAfter": "also not a date"}
    with caplog.at_level(logging.DEBUG, logger="asm.tls_inspect"):
        info = parse_cert_dict(cert, "example.com", "TLSv1.3", False, None)

    assert info.not_before == "" and info.not_after == ""
    assert info.expired is False and info.not_yet_valid is False
    messages = [r.getMessage() for r in caplog.records]
    assert any("Unparseable certificate notBefore" in m for m in messages)
    assert any("Unparseable certificate notAfter" in m for m in messages)


def test_error_while_closing_a_port_connection_is_logged(caplog):
    async def _scan():
        reader = AsyncMock(spec=asyncio.StreamReader)
        writer = AsyncMock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = True
        writer.wait_closed.side_effect = ConnectionResetError("reset by peer")
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            return await scan_single_port("93.184.216.34", 80, asyncio.Semaphore(1))

    with caplog.at_level(logging.DEBUG, logger="asm.portscan"):
        result = asyncio.run(_scan())

    assert result.state == "FILTERED"  # decided before the close; unchanged by the reset
    assert any("Error closing connection to 93.184.216.34:80" in r.getMessage()
               for r in caplog.records)
