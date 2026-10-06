"""v3.6c B-5: retention purge switches (D9). No database needed."""

from unittest.mock import MagicMock, patch

import pytest

from asm import retention
from asm.admin import build_parser
from asm.cli import build_parser as build_cli_parser
from asm.worker import worker as worker_module
from asm.worker.worker import ASMWorker


def _worker() -> ASMWorker:
    w = ASMWorker(engine=MagicMock())
    w.session_factory = MagicMock()
    return w


def test_purge_is_off_by_default(monkeypatch):
    monkeypatch.delenv("RETENTION_PURGE_ENABLED", raising=False)
    assert retention.purge_enabled() is False
    with patch.object(worker_module, "purge_expired") as purge:
        assert _worker().purge_retention_if_due() is None
    purge.assert_not_called()


@pytest.mark.parametrize("value", ["false", "0", "no", "", "maybe"])
def test_purge_stays_off_for_anything_but_an_explicit_yes(monkeypatch, value):
    monkeypatch.setenv("RETENTION_PURGE_ENABLED", value)
    assert retention.purge_enabled() is False


def test_enabled_purge_runs_once_per_hour(monkeypatch):
    monkeypatch.setenv("RETENTION_PURGE_ENABLED", "true")
    w = _worker()
    clock = iter([1000.0, 1000.0 + 3599, 1000.0 + 3600])
    with (
        patch.object(worker_module.time, "monotonic", side_effect=lambda: next(clock)),
        patch.object(worker_module, "purge_expired", return_value={"scans": 0}) as purge,
    ):
        assert w.purge_retention_if_due() == {"scans": 0}
        assert w.purge_retention_if_due() is None
        assert w.purge_retention_if_due() == {"scans": 0}
    assert purge.call_count == 2
    assert all(call.kwargs == {"dry_run": False} for call in purge.call_args_list)


@pytest.mark.parametrize(
    "parse",
    [
        lambda a: build_parser().parse_args(a),
        lambda a: build_cli_parser().parse_args(["admin", *a]),
    ],
)
def test_admin_purge_requires_an_explicit_mode(parse):
    with pytest.raises(SystemExit):
        parse(["purge"])
    with pytest.raises(SystemExit):
        parse(["purge", "--dry-run", "--execute"])
    assert parse(["purge", "--dry-run"]).dry_run is True
    assert parse(["purge", "--execute"]).dry_run is False
