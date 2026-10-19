"""F1 (independent check 2026-10-19): dependencies come from a hashed lock.

uv.lock is the source of truth. requirements/runtime.lock.txt and
requirements/dev.lock.txt are exported from it with hashes; the Docker image and
every CI install use them with --require-hashes, and pip-audit audits the lock
instead of whatever pip resolved on the day.
"""

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_LOCK = ROOT / "requirements" / "runtime.lock.txt"
DEV_LOCK = ROOT / "requirements" / "dev.lock.txt"
WORKFLOWS = ROOT / ".github" / "workflows"


def _name(requirement: str) -> str:
    """Normalised distribution name of a PEP 508 requirement string."""
    raw = re.split(r"[\s\[<>=!~;]", requirement.strip(), maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", raw).lower()


def _locked(path: Path) -> dict[str, str]:
    """Map each locked name to its full requirement block (pin line plus hash lines)."""
    blocks: dict[str, str] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            current = _name(line)
            blocks[current] = line
        elif current is not None:
            blocks[current] += "\n" + line
    return blocks


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _run_steps(workflow: str) -> list[str]:
    data = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    return [
        step.get("run", "")
        for job in data["jobs"].values()
        for step in job.get("steps", [])
    ]


def test_uv_lock_is_committed_alongside_pyproject():
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert lock.startswith("version = ")
    assert 'requires-python = ">=3.11"' in lock


def test_every_locked_requirement_is_pinned_with_hashes():
    for path in (RUNTIME_LOCK, DEV_LOCK):
        blocks = _locked(path)
        assert blocks, f"{path.name} is empty"
        for name, block in blocks.items():
            pin = block.splitlines()[0]
            assert re.match(r"^[A-Za-z0-9._\[\],-]+==\S+", pin), f"{path.name}: {pin!r}"
            assert "--hash=sha256:" in block, f"{path.name}: {name} has no hash"


def test_runtime_lock_covers_every_runtime_dependency():
    locked = _locked(RUNTIME_LOCK)
    for req in _pyproject()["project"]["dependencies"]:
        assert _name(req) in locked, f"{req} missing from runtime.lock.txt"
    for req in _pyproject()["project"]["optional-dependencies"]["dev"]:
        assert _name(req) not in locked, f"dev dependency {req} leaked into the runtime lock"


def test_dev_lock_covers_runtime_and_dev_dependencies():
    locked = _locked(DEV_LOCK)
    project = _pyproject()["project"]
    for req in project["dependencies"] + project["optional-dependencies"]["dev"]:
        assert _name(req) in locked, f"{req} missing from dev.lock.txt"


def test_docker_image_installs_the_runtime_lock_with_hash_checking():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "requirements/runtime.lock.txt" in dockerfile
    assert re.search(
        r"pip install[^\n]*--require-hashes[^\n]*-r [^\n]*runtime\.lock\.txt", dockerfile
    ), "runtime dependencies must be installed from the lock with --require-hashes"
    # The project wheel must not pull anything the lock did not pin.
    assert re.search(r"pip install[^\n]*--no-deps[^\n]*/wheels/\*\.whl", dockerfile)


def test_ci_installs_dependencies_only_from_the_dev_lock():
    for workflow in ("ci.yml", "security.yml"):
        for run in _run_steps(workflow):
            assert 'pip install -e ".[dev]"' not in run, f"{workflow} resolves deps unlocked"
            if "pip install -e" in run:
                assert "--no-deps" in run, f"{workflow}: editable install must be --no-deps"
    installs = [r for r in _run_steps("ci.yml") if "requirements/dev.lock.txt" in r]
    assert installs and all("--require-hashes" in r for r in installs)


def test_pip_audit_audits_the_lock_and_checks_it_is_current():
    runs = "\n".join(_run_steps("security.yml"))
    audit = next(line for line in runs.splitlines() if line.strip().startswith("pip-audit"))
    assert "requirements/dev.lock.txt" in audit
    assert "--strict" in audit
    assert "uv lock --check" in runs, "CI must fail when uv.lock is out of date"
    for lock in ("runtime.lock.txt", "dev.lock.txt"):
        assert f"requirements/{lock}" in runs and "uv export" in runs
