"""Unit tests for asynchronous TCP port scanner and service identification."""

from __future__ import annotations

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from asm.models import HostProbeStatus, PortStatus
from asm.portscan import (
    DEFAULT_PORTS,
    compute_risk_flags,
    grab_banner,
    run_port_scan,
    sanitize_banner,
    scan_host_ports,
    scan_single_port,
)


class TestRiskFlagsAndFixedPorts:
    """Test suite for risk flag rules and fixed port constraints."""

    def test_fixed_port_list_exact_membership(self):
        """Verify only the specified 16 common ports are in DEFAULT_PORTS."""
        expected = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
        ]
        assert DEFAULT_PORTS == expected

    def test_disallowed_port_rejected(self):
        """Verify scanning any port outside DEFAULT_PORTS raises ValueError."""
        async def _test():
            sem = asyncio.Semaphore(10)
            with pytest.raises(ValueError, match="not permitted"):
                await scan_single_port("example.com", 1337, sem)

        asyncio.run(_test())

    def test_risk_flags_databases(self):
        """Verify database ports trigger DATABASE_EXPOSURE."""
        for port in (3306, 5432, 6379):
            flags = compute_risk_flags(port)
            assert "DATABASE_EXPOSURE" in flags

    def test_risk_flags_remote_access_and_smb(self):
        """Verify RDP, SMB, and Telnet trigger appropriate exposure flags."""
        assert "RDP_EXPOSURE" in compute_risk_flags(3389)
        assert "SMB_EXPOSURE" in compute_risk_flags(445)

        telnet_flags = compute_risk_flags(23)
        assert "TELNET_INSECURE_REMOTE_ACCESS" in telnet_flags
        assert "PLAINTEXT_PROTOCOL" in telnet_flags

    def test_risk_flags_plaintext_rules(self):
        """Verify PLAINTEXT_PROTOCOL applies only to 21, 23, 25, 110, 143.

        Specifically, ports 80, 8080, 443, 8443, and 22 must NOT be flagged as plaintext.
        """
        # Flagged as plaintext
        for port in (21, 23, 25, 110, 143):
            assert "PLAINTEXT_PROTOCOL" in compute_risk_flags(port)

        # NOT flagged as plaintext
        for port in (80, 8080, 443, 8443, 22):
            assert "PLAINTEXT_PROTOCOL" not in compute_risk_flags(port)


class TestBannerGrabbingAndSanitization:
    """Test suite for safe banner reading and character sanitization."""

    def test_sanitize_banner_strips_control_characters(self):
        """Verify binary control chars are removed while keeping printable text."""
        raw = b"\x00\x1b[31mSSH-2.0-OpenSSH_8.9p1\r\n\x07"
        cleaned = sanitize_banner(raw)
        assert cleaned == "[31mSSH-2.0-OpenSSH_8.9p1"

    def test_sanitize_banner_empty_and_truncate(self):
        """Verify empty banners return None and long banners cap at 256 chars."""
        assert sanitize_banner(b"") is None
        assert sanitize_banner(b"   \r\n\t  ") is None

        long_raw = b"A" * 300
        cleaned = sanitize_banner(long_raw)
        assert cleaned is not None
        assert len(cleaned) == 256

    def test_banner_ssh_port_22_sends_nothing(self):
        """Verify port 22 receives NO bytes before banner read (SSH speaks first)."""
        async def _test():
            mock_reader = AsyncMock(spec=asyncio.StreamReader)
            mock_writer = AsyncMock(spec=asyncio.StreamWriter)
            mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

            banner = await grab_banner(mock_reader, mock_writer, 22)
            assert banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            mock_writer.write.assert_not_called()

        asyncio.run(_test())

    def test_banner_prompt_ports_send_crlf(self):
        """Verify ports 21, 25, 110, 143 send CRLF prompt."""
        async def _test():
            for port in (21, 25, 110, 143):
                mock_reader = AsyncMock(spec=asyncio.StreamReader)
                mock_writer = AsyncMock(spec=asyncio.StreamWriter)
                mock_reader.read.return_value = b"220 Service Ready\r\n"

                banner = await grab_banner(mock_reader, mock_writer, port)
                assert banner == "220 Service Ready"
                mock_writer.write.assert_called_once_with(b"\r\n")

        asyncio.run(_test())

    def test_banner_http_port_80_sends_nothing(self):
        """Verify non-prompt ports send nothing and listen passively."""
        async def _test():
            mock_reader = AsyncMock(spec=asyncio.StreamReader)
            mock_writer = AsyncMock(spec=asyncio.StreamWriter)
            mock_reader.read.return_value = b""

            banner = await grab_banner(mock_reader, mock_writer, 80)
            assert banner is None
            mock_writer.write.assert_not_called()

        asyncio.run(_test())


class TestPortClassification:
    """Test suite for OPEN, CLOSED, and FILTERED status mapping."""

    def test_port_open_success(self):
        """Verify successful TCP connection maps to OPEN."""
        async def _test():
            mock_reader = AsyncMock(spec=asyncio.StreamReader)
            mock_writer = AsyncMock(spec=asyncio.StreamWriter)
            mock_reader.read.return_value = b"SSH-2.0-Test\r\n"

            sem = asyncio.Semaphore(10)
            with patch(
                "asyncio.open_connection",
                new_callable=AsyncMock,
                return_value=(mock_reader, mock_writer),
            ):
                res = await scan_single_port("example.com", 22, sem)

            assert res.state == PortStatus.OPEN.value
            assert res.port == 22
            assert res.service_guess == "ssh (guess by port)"
            assert res.banner == "SSH-2.0-Test"

        asyncio.run(_test())

    def test_port_closed_on_connection_refused(self):
        """Verify ConnectionRefusedError maps strictly to CLOSED (host up, port closed)."""
        async def _test():
            sem = asyncio.Semaphore(10)
            with patch(
                "asyncio.open_connection",
                new_callable=AsyncMock,
                side_effect=ConnectionRefusedError("Connection refused"),
            ):
                res = await scan_single_port("example.com", 80, sem)

            assert res.state == PortStatus.CLOSED.value
            assert res.port == 80

        asyncio.run(_test())

    def test_port_filtered_on_timeout(self):
        """Verify TimeoutError maps strictly to FILTERED (likely firewall)."""
        async def _test():
            sem = asyncio.Semaphore(10)
            with patch(
                "asyncio.open_connection",
                new_callable=AsyncMock,
                side_effect=TimeoutError("Connect timed out"),
            ):
                res = await scan_single_port("example.com", 445, sem)

            assert res.state == PortStatus.FILTERED.value
            assert res.port == 445

        asyncio.run(_test())

    def test_refused_and_timeout_map_to_different_states(self):
        """Assert ConnectionRefusedError and TimeoutError map to distinct states."""
        async def _test():
            sem = asyncio.Semaphore(10)

            with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
                res_refused = await scan_single_port("example.com", 80, sem)

            with patch("asyncio.open_connection", side_effect=TimeoutError()):
                res_timeout = await scan_single_port("example.com", 80, sem)

            assert res_refused.state == PortStatus.CLOSED.value
            assert res_timeout.state == PortStatus.FILTERED.value
            assert res_refused.state != res_timeout.state

        asyncio.run(_test())

    def test_unusable_connection_when_closing_maps_to_filtered(self):
        """Verify that if writer.is_closing() is True, port is FILTERED (never OPEN)."""
        async def _test():
            mock_reader = AsyncMock(spec=asyncio.StreamReader)
            mock_writer = AsyncMock(spec=asyncio.StreamWriter)
            mock_writer.is_closing.return_value = True

            sem = asyncio.Semaphore(10)
            with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
                res = await scan_single_port("example.com", 80, sem)

            assert res.state == PortStatus.FILTERED.value

        asyncio.run(_test())

    def test_unusable_connection_when_at_eof_maps_to_filtered(self):
        """Verify that if reader.at_eof() is True immediately, port is FILTERED (never OPEN)."""
        async def _test():
            mock_reader = AsyncMock(spec=asyncio.StreamReader)
            mock_writer = AsyncMock(spec=asyncio.StreamWriter)
            mock_reader.at_eof.return_value = True

            sem = asyncio.Semaphore(10)
            with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
                res = await scan_single_port("example.com", 80, sem)

            assert res.state == PortStatus.FILTERED.value

        asyncio.run(_test())

    def test_oserror_unreachable_maps_to_filtered(self):
        """Verify OSError other than connection refused maps strictly to FILTERED."""
        async def _test():
            sem = asyncio.Semaphore(10)
            with patch("asyncio.open_connection", side_effect=OSError("Network unreachable")):
                res = await scan_single_port("example.com", 80, sem)

            assert res.state == PortStatus.FILTERED.value

        asyncio.run(_test())

    def test_general_exception_never_open(self):
        """Verify any unexpected exception maps to FILTERED, never OPEN."""
        async def _test():
            sem = asyncio.Semaphore(10)
            with patch("asyncio.open_connection", side_effect=RuntimeError("Unexpected error")):
                res = await scan_single_port("example.com", 80, sem)

            assert res.state == PortStatus.FILTERED.value

        asyncio.run(_test())


class TestHostScanFlowAndSafety:
    """Test suite for host scanning, SSRF protection, and error resilience."""

    def test_host_fails_dns_at_scan_time_skipped_unresolved(self):
        """Verify host failing DNS at scan time is marked SKIPPED_UNRESOLVED and scan continues."""
        async def _test():
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = Exception("NXDOMAIN")

            host_sem = asyncio.Semaphore(5)
            res = await scan_host_ports(
                "unresolved.example.com",
                "example.com",
                host_sem,
                resolver=mock_resolver,
            )

            assert res.status == HostProbeStatus.SKIPPED_UNRESOLVED.value
            assert "failed DNS resolution" in (res.skip_reason or "")
            assert res.open_ports == []

        asyncio.run(_test())

    def test_host_with_private_ip_skipped(self):
        """Verify host resolving to private IP is skipped as SKIPPED_PRIVATE_IP."""
        async def _test():
            mock_resolver = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.to_text.return_value = "10.0.0.5"
            mock_resolver.resolve.return_value = [mock_rdata]

            host_sem = asyncio.Semaphore(5)
            res = await scan_host_ports(
                "internal.example.com",
                "example.com",
                host_sem,
                resolver=mock_resolver,
            )

            assert res.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
            assert "non-public/private IP: 10.0.0.5" in (res.skip_reason or "")

        asyncio.run(_test())

    def test_untrusted_host_skipped(self):
        """Verify out-of-scope or malformed host is skipped as SKIPPED_UNTRUSTED."""
        async def _test():
            host_sem = asyncio.Semaphore(5)
            res = await scan_host_ports("attacker.org", "example.com", host_sem)
            assert res.status == HostProbeStatus.SKIPPED_UNTRUSTED.value

        asyncio.run(_test())

    def test_run_port_scan_success(self):
        """Verify run_port_scan successfully scans resolved hosts and aggregates results."""
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"
        mock_resolver.resolve.return_value = [mock_rdata]

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)
        mock_reader.read.return_value = b""

        # Port 80 is open, all others closed
        async def mock_open_conn(host, port):
            if port == 80:
                return mock_reader, mock_writer
            raise ConnectionRefusedError()

        with (
            patch("asyncio.open_connection", side_effect=mock_open_conn),
            patch("asyncio.sleep", return_value=None),
        ):
            results = run_port_scan(
                ["api.example.com"],
                "example.com",
                resolver=mock_resolver,
            )

        assert len(results) == 1
        res = results[0]
        assert res.status == HostProbeStatus.PROBED.value
        assert len(res.open_ports) == 1
        assert res.open_ports[0].port == 80
        assert len(res.closed_ports) == 15
        assert len(res.filtered_ports) == 0


class TestDnsDoesNotBlockEventLoop:
    """v3.6b B-2 (bug g): DNS lookups for different hosts run at the same time."""

    def test_host_lookups_overlap(self):
        barrier = threading.Barrier(3, timeout=5)

        class OverlapResolver:
            lifetime = timeout = 0

            def resolve(self, hostname, rdtype):
                if rdtype != "A":
                    raise dns.resolver.NoAnswer()
                # Passes only if 3 lookups are in flight together. If resolution ran on
                # the event loop, they would run one by one, the barrier would break,
                # and the host would end up SKIPPED_UNRESOLVED.
                barrier.wait()
                rdata = MagicMock()
                rdata.to_text.return_value = "10.0.0.5"  # private: no port is touched
                return [rdata]

        results = run_port_scan(
            ["a.example.com", "b.example.com", "c.example.com"],
            "example.com",
            resolver=OverlapResolver(),
        )

        assert [r.status for r in results] == [HostProbeStatus.SKIPPED_PRIVATE_IP.value] * 3
