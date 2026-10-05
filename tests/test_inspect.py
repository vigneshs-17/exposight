"""Unit tests for TLS certificate and HTTP security headers inspection.

All tests are strictly offline and mocked (zero network calls).
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest

from asm.headers_inspect import (
    extract_header_info,
    inspect_single_host,
    parse_hsts_header,
    run_inspection,
)
from asm.models import HostProbeStatus
from asm.tls_inspect import (
    matches_hostname,
    parse_cert_dict,
)


def _stream_cm(response: MagicMock) -> MagicMock:
    """Wrap a mock response so it can stand in for ``httpx.Client.stream(...)``."""
    cm = MagicMock()
    cm.__enter__.return_value = response
    cm.__exit__.return_value = False
    return cm


class TestTLSCertificateParsing:
    """Test suite for parsing getpeercert() dictionaries and evaluating flags."""

    @pytest.fixture
    def sample_cert_dict(self) -> dict:
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert Global Root CA"),),),
            "version": 3,
            "serialNumber": "0123456789ABCDEF",
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        }

    def test_cert_valid_and_trusted(self, sample_cert_dict: dict) -> None:
        """Verify normal valid certificate properties and flags."""
        now = datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
        cert = parse_cert_dict(
            cert_dict=sample_cert_dict,
            hostname="example.com",
            tls_version="TLSv1.3",
            is_trusted=True,
            verify_error=None,
            source="from_response",
            now_utc=now,
        )

        assert cert.is_trusted is True
        assert cert.verify_error is None
        assert cert.source == "from_response"
        assert cert.subject_cn == "example.com"
        assert "example.com" in cert.sans
        assert "*.example.com" in cert.sans
        assert cert.hostname_matches is True
        assert cert.hostname_mismatch is False
        assert cert.expired is False
        assert cert.not_yet_valid is False
        assert cert.expiring_soon is False
        assert cert.issuer_equals_subject is False
        assert cert.deprecated_tls is False
        assert cert.days_until_expiry > 100

    def test_cert_expired(self, sample_cert_dict: dict) -> None:
        """Verify expired certificate flag when now is past notAfter."""
        now = datetime.datetime(2027, 1, 15, 0, 0, 0, tzinfo=datetime.UTC)
        cert = parse_cert_dict(
            cert_dict=sample_cert_dict,
            hostname="example.com",
            tls_version="TLSv1.3",
            is_trusted=True,
            verify_error=None,
            now_utc=now,
        )

        assert cert.expired is True
        assert cert.days_until_expiry < 0
        assert cert.expiring_soon is False  # Expired certs are not 'expiring soon'

    def test_cert_not_yet_valid(self, sample_cert_dict: dict) -> None:
        """Verify not_yet_valid flag when now is before notBefore."""
        now = datetime.datetime(2025, 12, 1, 0, 0, 0, tzinfo=datetime.UTC)
        cert = parse_cert_dict(
            cert_dict=sample_cert_dict,
            hostname="example.com",
            tls_version="TLSv1.3",
            is_trusted=True,
            verify_error=None,
            now_utc=now,
        )

        assert cert.not_yet_valid is True
        assert cert.expired is False

    def test_cert_issuer_equals_subject(self) -> None:
        """Verify issuer_equals_subject flag for self-signed certificates."""
        self_signed_dict = {
            "subject": ((("commonName", "selfsigned.local"),),),
            "issuer": ((("commonName", "selfsigned.local"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "selfsigned.local"),),
        }
        now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
        cert = parse_cert_dict(
            cert_dict=self_signed_dict,
            hostname="selfsigned.local",
            tls_version="TLSv1.3",
            is_trusted=False,
            verify_error="self-signed certificate",
            now_utc=now,
        )

        assert cert.issuer_equals_subject is True
        assert cert.is_trusted is False

    def test_hostname_mismatch(self, sample_cert_dict: dict) -> None:
        """Verify hostname_mismatch flag when hostname does not match SANs/CN."""
        now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
        cert = parse_cert_dict(
            cert_dict=sample_cert_dict,
            hostname="unrelated-domain.com",
            tls_version="TLSv1.3",
            is_trusted=True,
            verify_error=None,
            now_utc=now,
        )

        assert cert.hostname_matches is False
        assert cert.hostname_mismatch is True

    def test_expiring_soon_boundary(self, sample_cert_dict: dict) -> None:
        """Verify expiring_soon boundary condition (<= 30 days)."""
        # notAfter is Dec 31 23:59:59 2026 GMT
        # Dec 1 = 30.9 days remaining (expiring_soon = False)
        now_31_days = datetime.datetime(2026, 11, 30, 23, 59, 59, tzinfo=datetime.UTC)
        cert_31 = parse_cert_dict(
            sample_cert_dict, "example.com", "TLSv1.3", True, None, now_utc=now_31_days
        )
        assert cert_31.expiring_soon is False

        # Dec 2 = 29.9 days remaining (expiring_soon = True)
        now_29_days = datetime.datetime(2026, 12, 2, 0, 0, 0, tzinfo=datetime.UTC)
        cert_29 = parse_cert_dict(
            sample_cert_dict, "example.com", "TLSv1.3", True, None, now_utc=now_29_days
        )
        assert cert_29.expiring_soon is True

    def test_deprecated_tls_version(self, sample_cert_dict: dict) -> None:
        """Verify deprecated_tls flag for TLS 1.0/1.1 vs modern versions."""
        now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
        cert_old = parse_cert_dict(
            sample_cert_dict, "example.com", "TLSv1", True, None, now_utc=now
        )
        assert cert_old.deprecated_tls is True

        cert_old_11 = parse_cert_dict(
            sample_cert_dict, "example.com", "TLSv1.1", True, None, now_utc=now
        )
        assert cert_old_11.deprecated_tls is True

        cert_modern = parse_cert_dict(
            sample_cert_dict, "example.com", "TLSv1.2", True, None, now_utc=now
        )
        assert cert_modern.deprecated_tls is False


class TestRFC6125HostnameMatching:
    """Test suite for RFC 6125 wildcard and exact hostname matching."""

    def test_exact_match(self) -> None:
        assert matches_hostname("example.com", ["example.com"], None) is True
        assert matches_hostname("sub.example.com", ["sub.example.com"], None) is True
        assert matches_hostname("other.com", ["example.com"], None) is False

    def test_wildcard_single_label(self) -> None:
        assert matches_hostname("api.example.com", ["*.example.com"], None) is True
        assert matches_hostname("app.example.com", ["*.example.com"], None) is True

    def test_wildcard_does_not_match_root(self) -> None:
        assert matches_hostname("example.com", ["*.example.com"], None) is False

    def test_wildcard_does_not_match_multi_level(self) -> None:
        assert matches_hostname("dev.api.example.com", ["*.example.com"], None) is False


class TestSecurityHeadersInspection:
    """Test suite for security header extraction and HSTS evaluation."""

    def test_parse_hsts_header(self) -> None:
        # Standard strong HSTS
        max_age, weak = parse_hsts_header("max-age=31536000; includeSubDomains; preload")
        assert max_age == 31536000
        assert weak is False

        # Weak HSTS (less than 180 days = 15552000s)
        max_age_weak, weak2 = parse_hsts_header("max-age=86400")
        assert max_age_weak == 86400
        assert weak2 is True

        # Header present without max-age directive
        max_age_none, weak3 = parse_hsts_header("includeSubDomains")
        assert max_age_none is None
        assert weak3 is True

        # Missing header
        max_age_empty, weak4 = parse_hsts_header(None)
        assert max_age_empty is None
        assert weak4 is False

    def test_extract_header_info_all_present(self) -> None:
        raw_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319",
        }
        info = extract_header_info(raw_headers)

        assert len(info.present_headers) == 6
        assert len(info.missing_headers) == 0
        assert info.hsts_weak is False
        assert info.hsts_max_age == 31536000
        assert info.server_disclosed is True
        assert info.server == "nginx/1.18.0"
        assert info.x_powered_by_disclosed is True
        assert info.x_aspnet_version_disclosed is True

    def test_extract_header_info_missing_headers(self) -> None:
        raw_headers = {
            "Content-Type": "text/html",
        }
        info = extract_header_info(raw_headers)

        assert len(info.present_headers) == 0
        assert len(info.missing_headers) == 6
        assert "Strict-Transport-Security" in info.missing_headers
        assert "Content-Security-Policy" in info.missing_headers
        assert info.server_disclosed is False
        assert info.x_powered_by_disclosed is False


class TestSingleHostInspectionAndFallbacks:
    """Test single host inspection with single-connection preference and robust fallbacks."""

    def test_inspect_from_response_success(self) -> None:
        """Verify successful single-connection extraction of cert and headers from response."""
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }
        mock_response.iter_raw.return_value = [b"<html>Test</html>"]

        mock_stream = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.getpeercert.return_value = {
            "subject": ((("commonName", "test.example.com"),),),
            "issuer": ((("commonName", "DigiCert"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "test.example.com"),),
        }
        mock_stream.get_extra_info.return_value = mock_ssl_sock
        mock_response.extensions = {"network_stream": mock_stream}

        with patch("httpx.Client.stream", return_value=_stream_cm(mock_response)):
            res = inspect_single_host("test.example.com", "example.com")

        assert res.status == HostProbeStatus.PROBED.value
        assert res.cert is not None
        assert res.cert.source == "from_response"
        assert res.cert.subject_cn == "test.example.com"
        assert res.headers is not None
        assert "Strict-Transport-Security" in res.headers.present_headers

    def test_fallback_when_getpeercert_returns_empty_dict(self) -> None:
        """User Requirement 2: If getpeercert() returns {} on response, fallback path is used."""
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.headers = {"X-Frame-Options": "DENY"}
        mock_response.iter_raw.return_value = [b""]

        mock_stream = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = {}  # Empty dict!
        mock_stream.get_extra_info.return_value = mock_ssl_sock
        mock_response.extensions = {"network_stream": mock_stream}

        # Mock direct socket fallback returning the cert
        fallback_cert = MagicMock()
        fallback_cert.source = "from_socket"

        with (
            patch("httpx.Client.stream", return_value=_stream_cm(mock_response)),
            patch(
                "asm.headers_inspect.connect_and_inspect_cert_socket", return_value=fallback_cert
            ) as mock_fallback,
        ):
            res = inspect_single_host("test.example.com", "example.com")

        assert mock_fallback.called
        assert res.cert is not None
        assert res.cert.source == "from_socket"

    def test_fallback_when_network_stream_is_none(self) -> None:
        """User Requirement 2: If network_stream is missing/None, fallback path is used."""
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.headers = {"X-Frame-Options": "DENY"}
        mock_response.iter_raw.return_value = [b""]
        mock_response.extensions = {}  # No network_stream!

        fallback_cert = MagicMock()
        fallback_cert.source = "from_socket"

        with (
            patch("httpx.Client.stream", return_value=_stream_cm(mock_response)),
            patch(
                "asm.headers_inspect.connect_and_inspect_cert_socket", return_value=fallback_cert
            ) as mock_fallback,
        ):
            res = inspect_single_host("test.example.com", "example.com")

        assert mock_fallback.called
        assert res.cert is not None
        assert res.cert.source == "from_socket"

    def test_port_443_genuinely_closed_returns_null_cert(self) -> None:
        """User Requirement 2: Port 443 closed -> cert=None with clear reason, no hang."""
        with (
            patch(
                "httpx.Client.stream", side_effect=ConnectionRefusedError("Connection refused")
            ),
            patch("asm.headers_inspect.connect_and_inspect_cert_socket", return_value=None),
        ):
            res = inspect_single_host("closed.example.com", "example.com")

        assert res.cert is None
        assert res.headers is None
        assert "unreachable" in (res.skip_reason or "").lower()

    def test_header_fetch_failure_handled_gracefully(self) -> None:
        """Verify that failure to fetch HTTP headers does not crash the host inspection."""
        mock_cert = MagicMock()
        mock_cert.source = "from_socket"

        with (
            patch("httpx.Client.stream", side_effect=Exception("Read timeout")),
            patch("asm.headers_inspect.connect_and_inspect_cert_socket", return_value=mock_cert),
        ):
            res = inspect_single_host("timeout.example.com", "example.com")

        assert res.cert is not None
        assert res.cert.source == "from_socket"


class TestRunInspectionWorkflowAndSafety:
    """Test suite for run_inspection coordinator and safety controls."""

    def test_untrusted_host_skipped(self) -> None:
        probe_results = [
            {
                "subdomain": "attacker.com",
                "status": "PROBED",
                "https": {"reachable": True},
            }
        ]
        report = run_inspection(probe_results, "example.com", "test_report.json")
        assert report.counts["skipped_untrusted"] == 1
        assert report.results[0].status == HostProbeStatus.SKIPPED_UNTRUSTED.value

    def test_private_ip_skipped(self) -> None:
        probe_results = [
            {
                "subdomain": "internal.example.com",
                "status": "PROBED",
                "https": {"reachable": True},
            }
        ]
        with patch("asm.scan_common.resolve_host_ips", return_value=["192.168.1.100"]):
            report = run_inspection(probe_results, "example.com", "test_report.json")

        assert report.counts["skipped_private_ip"] == 1
        assert report.results[0].status == HostProbeStatus.SKIPPED_PRIVATE_IP.value

    def test_non_https_host_skipped(self) -> None:
        """User Requirement 7: Keep SKIPPED_NOT_HTTPS for hosts not reachable over HTTPS."""
        probe_results = [
            {
                "subdomain": "http-only.example.com",
                "status": "PROBED",
                "https": {"reachable": False},
            },
            {
                "subdomain": "unresolved.example.com",
                "status": "SKIPPED_UNRESOLVED",
            },
        ]
        report = run_inspection(probe_results, "example.com", "test_report.json")
        assert report.counts["skipped_not_https"] == 2
        assert report.results[0].status == HostProbeStatus.SKIPPED_NOT_HTTPS.value
        assert report.results[1].status == HostProbeStatus.SKIPPED_NOT_HTTPS.value


class TestInspectStreamingAndSSRF:
    """P1 hardening: bounded body reads, first-hop certificate, SSRF-checked redirects."""

    def test_body_read_is_capped(self) -> None:
        """A huge body is never read past MAX_RESPONSE_BYTES."""
        consumed = {"chunks": 0}

        def endless_body():
            for _ in range(10_000):  # ~40 MB if fully read
                consumed["chunks"] += 1
                yield b"X" * 4096

        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_response.iter_raw.return_value = endless_body()
        mock_response.extensions = {}

        with (
            patch("httpx.Client.stream", return_value=_stream_cm(mock_response)),
            patch("asm.headers_inspect.connect_and_inspect_cert_socket", return_value=None),
        ):
            res = inspect_single_host("big.example.com", "example.com")

        assert consumed["chunks"] <= (65536 // 4096) + 1
        assert res.headers is not None

    def test_redirect_to_private_ip_host_is_not_followed(self) -> None:
        """An in-scope redirect target that resolves to a metadata IP is never requested."""
        first = MagicMock()
        first.is_redirect = True
        first.headers = {"location": "https://meta.example.com/", "X-Frame-Options": "DENY"}
        first.iter_raw.return_value = [b""]
        first.extensions = {}

        with (
            patch("httpx.Client.stream", return_value=_stream_cm(first)) as mock_stream,
            patch("asm.scan_common.resolve_host_ips", return_value=["169.254.169.254"]),
            patch("asm.headers_inspect.connect_and_inspect_cert_socket", return_value=None),
        ):
            res = inspect_single_host("sso.example.com", "example.com")

        assert mock_stream.call_count == 1
        assert res.headers is not None

    def test_unresolved_host_reported_as_unresolved(self) -> None:
        """run_inspection reports hosts with no DNS answer as SKIPPED_UNRESOLVED."""
        probe_results = [
            {"subdomain": "ghost.example.com", "status": "PROBED", "https": {"reachable": True}}
        ]
        with patch("asm.scan_common.resolve_host_ips", return_value=[]):
            report = run_inspection(probe_results, "example.com", "test_report.json")

        assert report.counts["skipped_unresolved"] == 1
        assert report.counts["skipped_private_ip"] == 0
        assert report.results[0].status == HostProbeStatus.SKIPPED_UNRESOLVED.value
