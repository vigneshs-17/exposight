"""Tests for scripts/deploy_remote.sh and deployment script safety invariants."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_REMOTE_SCRIPT = REPO_ROOT / "scripts" / "deploy_remote.sh"
DEPLOY_PS1_SCRIPT = REPO_ROOT / "scripts" / "deploy.ps1"


def get_bash_executable() -> str:
    """Find bash executable on Linux or Windows."""
    found = shutil.which("bash")
    if found:
        return found

    # Search common Git bash locations on Windows
    git = shutil.which("git")
    if git:
        git_dir = Path(git).parent.parent
        for candidate in [git_dir / "bin" / "bash.exe", git_dir / "usr" / "bin" / "bash.exe"]:
            if candidate.exists():
                return str(candidate)

    for candidate in [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"D:\git\Git\bin\bash.exe",
        r"D:\git\Git\usr\bin\bash.exe",
    ]:
        if Path(candidate).exists():
            return candidate

    pytest.skip("bash executable not available to run deploy_remote.sh locally")


def test_script_has_lf_line_endings() -> None:
    """The script must strictly use Unix LF line endings (no CR / CRLF)."""
    raw_bytes = DEPLOY_REMOTE_SCRIPT.read_bytes()
    assert b"\r" not in raw_bytes, (
        "scripts/deploy_remote.sh contains Windows CRLF line endings (\\r)"
    )


def test_script_starts_with_set_euo_pipefail() -> None:
    """The script must set -euo pipefail at the top after shebang/comments."""
    lines = [
        line.strip()
        for line in DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert lines, "Script is empty or contains only comments"
    assert lines[0] == "set -euo pipefail", (
        f"Expected 'set -euo pipefail' as first command line, got {lines[0]!r}"
    )


def test_final_non_empty_line_is_exit_0() -> None:
    """The final non-empty line of deploy_remote.sh must be 'exit 0'.

    Prevents bash from evaluating trailing CRLF appended by PowerShell.
    """
    lines = [
        line.strip()
        for line in DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert lines, "deploy_remote.sh is empty"
    assert lines[-1] == "exit 0", f"Expected 'exit 0' as final line, got {lines[-1]!r}"


def test_unknown_subcommand_exits_2() -> None:
    """An unknown subcommand must print a usage message and exit with code 2."""
    bash = get_bash_executable()
    res = subprocess.run(
        [bash, str(DEPLOY_REMOTE_SCRIPT), "nope"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 2, f"Expected returncode 2, got {res.returncode}. Stderr: {res.stderr}"
    assert "Usage:" in res.stderr
    assert "{precheck|backup|incoming|pull|up|verify}" in res.stderr


def test_no_destructive_commands() -> None:
    """The script must not contain hard resets, forced git operations, push, or DB restores."""
    content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    assert "reset --hard" not in content, "deploy_remote.sh must not contain 'reset --hard'"
    assert not re.search(
        r"(?<!-)--force\b(?!-recreate)", content
    ), "deploy_remote.sh must not contain '--force' flags"
    assert "git push" not in content, "deploy_remote.sh must not push to remotes"
    assert "pg_restore" not in content, (
        "deploy_remote.sh must not run pg_restore (restores are manual only)"
    )
    assert "DROP DATABASE" not in content, "deploy_remote.sh must not drop databases"


def test_every_sudo_uses_sudo_minus_n() -> None:
    """Every sudo command in deploy_remote.sh must use sudo -n for fail-fast execution."""
    content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    sudo_invocations = [
        line.strip()
        for line in content.splitlines()
        if re.search(r"(?:^|&&|\|\||;|if\s+!?)\s*sudo\b", line.strip())
        and not line.strip().startswith("echo")
    ]
    assert sudo_invocations, "Expected at least one sudo invocation in deploy_remote.sh"
    for line in sudo_invocations:
        assert re.search(r"\bsudo\s+-n\b", line), f"Found sudo invocation without -n flag: {line!r}"


def test_contains_no_strict_host_key_checking_disabling() -> None:
    """Neither deploy_remote.sh nor deploy.ps1 should disable host key checking."""
    remote_content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    ps1_content = DEPLOY_PS1_SCRIPT.read_text(encoding="utf-8")

    assert "StrictHostKeyChecking" not in remote_content
    assert "StrictHostKeyChecking" not in ps1_content
    assert "UserKnownHostsFile=/dev/null" not in ps1_content


def test_remote_script_prints_machine_readable_markers() -> None:
    """deploy_remote.sh must print the required machine-readable markers."""
    content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    required_markers = [
        "PRE_COMMIT=",
        "PRE_REVISION=",
        "BACKUP_PATH=",
        "BACKUP_BYTES=",
        "UP_STARTED=",
        "POST_REVISION=",
    ]
    for marker in required_markers:
        assert marker in content, f"Marker {marker!r} missing from deploy_remote.sh"


def test_verify_checks_last_line_for_egress_passed() -> None:
    """deploy_remote.sh must decide egress PASS from the last non-empty line, not grep."""
    content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    assert 'grep -q "egress check: PASSED"' not in content
    assert 'egress check: PASSED' in content


def test_verify_uses_since_for_worker_logs() -> None:
    """deploy_remote.sh must check worker logs using --since."""
    content = DEPLOY_REMOTE_SCRIPT.read_text(encoding="utf-8")
    assert "logs --since" in content
