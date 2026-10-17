"""Offline unit regression tests for scanner authorization and outbound-request safety hardening."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from asm.api.routes import queue_scan
from asm.db.models import Domain, ScanRun
from asm.db.scans import UnverifiedDomainError, enqueue_scan
from asm.scan_common import (
    check_host_for_ssrf,
    is_safe_public_ip,
    resolve_public_ips,
)
from asm.worker.worker import ASMWorker

# ==============================================================================
# 1. Outbound-Request Safety & IPv4-Translated IPv6 SSRF Protection
# ==============================================================================


@pytest.mark.parametrize(
    "ipv4_translated_ip",
    [
        "::ffff:0:127.0.0.1",       # Loopback
        "::ffff:0:169.254.169.254", # Cloud metadata (AWS/Azure/GCP)
        "::ffff:0:168.63.129.16",   # Azure WireServer
        "::ffff:0:10.0.0.1",        # RFC 1918 10/8
        "::ffff:0:192.168.1.1",     # RFC 1918 192.168/16
        "::ffff:0:172.16.0.1",      # RFC 1918 172.16/12
        "::ffff:0:100.64.0.1",      # CGNAT 100.64/10
        "::ffff:0:0.0.0.0",         # Unspecified
    ],
)
def test_is_safe_public_ip_rejects_ipv4_translated_forbidden_ips(ipv4_translated_ip: str) -> None:
    """is_safe_public_ip must reject RFC 6052 IPv4-translated addresses to forbidden targets."""
    assert is_safe_public_ip(ipv4_translated_ip) is False


def test_is_safe_public_ip_allows_public_ipv4_translated_ip() -> None:
    """is_safe_public_ip allows globally routable public addresses in IPv4-translated form."""
    assert is_safe_public_ip("::ffff:0:93.184.216.34") is True


def test_resolve_public_ips_refuses_ipv4_translated_loopback() -> None:
    """resolve_public_ips must fail closed when a hostname resolves to IPv4-translated loopback."""
    with patch("asm.scan_common.resolve_host_ips", return_value=["::ffff:0:127.0.0.1"]):
        ips, reason = resolve_public_ips("internal.example.com")
        assert ips is None
        assert reason is not None
        assert "non-public/private IP" in reason


def test_check_host_for_ssrf_blocks_ipv4_translated_metadata() -> None:
    """check_host_for_ssrf must report unsafe when host resolves to IPv4-translated metadata."""
    with patch("asm.scan_common.resolve_host_ips", return_value=["::ffff:0:169.254.169.254"]):
        is_safe, reason = check_host_for_ssrf("metadata.example.com")
        assert is_safe is False
        assert reason is not None
        assert "non-public/private IP" in reason


def test_resolve_public_ips_refuses_mixed_public_and_private_answers() -> None:
    """resolve_public_ips fails closed when DNS returns both public and private answers."""
    with patch(
        "asm.scan_common.resolve_host_ips",
        return_value=["93.184.216.34", "::ffff:0:127.0.0.1"],
    ):
        ips, reason = resolve_public_ips("mixed.example.com")
        assert ips is None
        assert reason is not None
        assert "non-public/private IP" in reason


def test_check_host_for_ssrf_blocks_redirect_target_with_mixed_answers() -> None:
    """check_host_for_ssrf blocks a redirect target if any answer in a mixed set is forbidden."""
    with patch(
        "asm.scan_common.resolve_host_ips",
        return_value=["93.184.216.34", "10.0.0.1"],
    ):
        is_safe, reason = check_host_for_ssrf("redirect-target.example.com")
        assert is_safe is False
        assert reason is not None
        assert "non-public/private IP" in reason


# ==============================================================================
# 2. Operator Override Expiry and Revoked Verification Gating
# ==============================================================================


def test_expired_operator_override_is_not_verified() -> None:
    """Domain.is_verified must return False when verification_expires_at has passed."""
    expired_domain = Domain(
        id=1,
        org_id=1,
        name="expired.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    assert expired_domain.is_verified is False


def test_active_operator_override_is_verified() -> None:
    """Domain.is_verified must return True when verification_expires_at is in the future."""
    active_domain = Domain(
        id=2,
        org_id=1,
        name="active.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=datetime.now(UTC) + timedelta(days=10),
    )
    assert active_domain.is_verified is True


def test_dns_txt_verified_without_expiry_is_verified() -> None:
    """Standard DNS TXT verification without expiry returns True."""
    txt_domain = Domain(
        id=3,
        org_id=1,
        name="txt.example.com",
        verification_status="verified",
        verification_method="dns_txt",
        verification_expires_at=None,
    )
    assert txt_domain.is_verified is True


def test_enqueue_scan_rejects_expired_operator_override() -> None:
    """enqueue_scan must raise UnverifiedDomainError when verification_expires_at has passed."""
    session = MagicMock(spec=Session)
    expired_domain = Domain(
        id=4,
        org_id=1,
        name="expired-scan.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    session.get.return_value = expired_domain

    with pytest.raises(UnverifiedDomainError, match="not verified"):
        enqueue_scan(session, domain_id=4, trigger="manual")


def test_queue_scan_api_rejects_expired_operator_override() -> None:
    """queue_scan API endpoint must return HTTP 422 for an expired domain."""
    db = MagicMock(spec=Session)
    expired_domain = Domain(
        id=5,
        org_id=10,
        name="expired-api.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )

    with patch("asm.api.routes.get_domain_for_org", return_value=expired_domain):
        with pytest.raises(HTTPException) as exc_info:
            queue_scan(
                org_id=10,
                domain_id=5,
                auth_context=(MagicMock(), MagicMock(role="admin")),
                db=db,
                response=MagicMock(),
            )
        assert exc_info.value.status_code == 422
        assert "not verified" in exc_info.value.detail


def test_execute_scan_run_rejects_expired_operator_override() -> None:
    """execute_scan_run must raise SecurityGateError if domain verification has expired."""
    session = MagicMock(spec=Session)
    session_factory = MagicMock(return_value=session)
    session.__enter__.return_value = session

    expired_domain = Domain(
        id=6,
        org_id=10,
        name="expired-worker.example.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=datetime.now(UTC) - timedelta(minutes=15),
    )
    session.get.return_value = expired_domain

    worker = ASMWorker(engine=MagicMock())
    worker.session_factory = session_factory
    worker._verify_fence = MagicMock()
    worker._mark_run_final = MagicMock()
    worker._skip_unfinished_stages = MagicMock()

    claim_token = uuid.uuid4()
    worker.execute_scan_run(
        scan_run_id=100,
        domain_id=6,
        claim_token=claim_token,
        attempts=1,
        max_attempts=3,
    )

    # Worker must terminate as failed with authorization error, not execute stages
    worker._mark_run_final.assert_called_once()
    assert worker._mark_run_final.call_args[0][2] == "failed"
    assert "verification is not active" in worker._mark_run_final.call_args[0][3]


# ==============================================================================
# 3. Suspended Organization Scan Blocking & Retry Protection
# ==============================================================================


def test_queue_scan_api_rejects_suspended_organization() -> None:
    """queue_scan API endpoint must return HTTP 403 when all owners are suspended."""
    db = MagicMock(spec=Session)
    verified_domain = Domain(
        id=7,
        org_id=20,
        name="suspended-org.example.com",
        verification_status="verified",
        verification_method="dns_txt",
    )

    with (
        patch("asm.api.routes.get_domain_for_org", return_value=verified_domain),
        patch("asm.api.routes.all_owners_suspended", return_value=True),
    ):
        with pytest.raises(HTTPException) as exc_info:
            queue_scan(
                org_id=20,
                domain_id=7,
                auth_context=(MagicMock(), MagicMock(role="admin")),
                db=db,
                response=MagicMock(),
            )
        assert exc_info.value.status_code == 403
        assert "Scanning is paused for this organization" in exc_info.value.detail


def test_execute_scan_run_rejects_suspended_organization() -> None:
    """execute_scan_run must terminate scan if organization owners are suspended."""
    session = MagicMock(spec=Session)
    session_factory = MagicMock(return_value=session)
    session.__enter__.return_value = session

    verified_domain = Domain(
        id=8,
        org_id=30,
        name="suspended-worker.example.com",
        verification_status="verified",
        verification_method="dns_txt",
    )
    session.get.return_value = verified_domain

    worker = ASMWorker(engine=MagicMock())
    worker.session_factory = session_factory
    worker._verify_fence = MagicMock()
    worker._mark_run_final = MagicMock()
    worker._skip_unfinished_stages = MagicMock()

    claim_token = uuid.uuid4()
    with patch("asm.worker.worker.all_owners_suspended", return_value=True):
        worker.execute_scan_run(
            scan_run_id=101,
            domain_id=8,
            claim_token=claim_token,
            attempts=1,
            max_attempts=3,
        )

    worker._mark_run_final.assert_called_once()
    assert worker._mark_run_final.call_args[0][2] == "failed"
    assert "Scanning is paused" in worker._mark_run_final.call_args[0][3]


def test_handle_unexpected_worker_exception_cancels_when_org_suspended() -> None:
    """_handle_unexpected_worker_exception must cancel run rather than requeue on org suspension."""
    session = MagicMock(spec=Session)
    session_factory = MagicMock(return_value=session)
    session.__enter__.return_value = session

    run = ScanRun(id=102, domain_id=9, status="running")
    domain = Domain(id=9, org_id=40, name="suspended-retry.example.com")

    def mock_get(model: type, pk: int) -> Any:
        if model is ScanRun:
            return run
        if model is Domain:
            return domain
        return None

    session.get.side_effect = mock_get

    worker = ASMWorker(engine=MagicMock())
    worker.session_factory = session_factory
    worker._verify_fence = MagicMock()

    claim_token = uuid.uuid4()
    with patch("asm.worker.worker.all_owners_suspended", return_value=True):
        worker._handle_unexpected_worker_exception(
            scan_run_id=102,
            claim_token=claim_token,
            error_msg="Connection reset by peer",
            attempts=1,
            max_attempts=3,
        )

    # Must execute cancellation update, not requeue update
    executed_sqls = [call[0][0].text for call in session.execute.call_args_list]
    assert any("status = 'cancelled'" in sql for sql in executed_sqls)
    assert not any("status = 'queued'" in sql for sql in executed_sqls)
    first_call_params = session.execute.call_args_list[0][0][1]
    assert first_call_params["error"] == "Scanning is paused for this organization."
