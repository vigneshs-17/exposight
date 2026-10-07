"""v3.6b B-1: user-visible text says Exposight, not the old ASM SaaS name.

The alert email subject is checked in tests/test_alerts.py.
"""

import re
import subprocess
from pathlib import Path

import pytest

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



# History and the guard tests themselves may name the old brand; the distribution
# name in pyproject.toml is kept until it is renamed on purpose.
ALLOWED_FILES = {
    "ENGINEERING_LOG.md",
    "STATUS.md",
    "tests/test_brand_text.py",
    "tests/test_dashboard_ui.py",
}
ALLOWED_LINES = {'name = "asm-saas"'}


def test_tracked_files_do_not_use_the_old_name():
    repo = PKG.parent.parent
    try:
        listed = subprocess.run(
            ["git", "ls-files"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    assert listed
    offenders = []
    for name in listed:
        path = repo / name
        if name in ALLOWED_FILES or "vendor" in path.parts or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # binary
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r"ASM SaaS|asm-saas", line) and line.strip() not in ALLOWED_LINES:
                offenders.append(f"{name}:{number}")
    assert offenders == []
