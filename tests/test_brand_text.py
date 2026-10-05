"""v3.6b B-1: user-visible text says Exposight, not the old ASM SaaS name.

The alert email subject is checked in tests/test_alerts.py.
"""

import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "src" / "asm"
OLD_NAME = re.compile(r"ASM SaaS|asm-saas|\bASM can\b|\[ASM\]")


def test_served_templates_and_static_files_use_exposight():
    served = [
        p
        for p in list((PKG / "templates").rglob("*.html")) + list((PKG / "static").rglob("*"))
        if p.is_file() and p.suffix in {".html", ".js", ".css"} and "vendor" not in p.parts
    ]
    assert served
    offenders = [str(p) for p in served if OLD_NAME.search(p.read_text(encoding="utf-8"))]
    assert offenders == []

