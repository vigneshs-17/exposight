"""Unit tests for active HTTP/HTTPS host prober and security controls."""

from __future__ import annotations

import ssl
import time
from unittest.mock import MagicMock, patch

import dns.resolver
import httpx
import pytest

from asm.models import HostProbeStatus, ProbeErrorType
from asm.prober import (
    CONNECT_TIMEOUT,
    MAX_BODY_BYTES,
    TOTAL_URL_TIMEOUT,
    _stream_and_read_body,
    check_host_for_ssrf,
    extract_title,
    is_redirect_in_scope,
    is_safe_public_ip,
    probe_host,
    probe_url,
)
from asm.scan_common import UNRESOLVED_REASON_PREFIX


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """Unit tests never use real DNS: a lookup without a test resolver answers a
    fixed public address (93.184.216.34). Scanners pin and connect to that IP; the
    MockTransport sees it in the URL and the hostname in the Host header."""
    import asm.scan_common as scan_common

    real = scan_common.resolve_host_ips

    def fake(hostname, resolver=None):
        return real(hostname, resolver=resolver) if resolver is not None else ["93.184.216.34"]

    monkeypatch.setattr(scan_common, "resolve_host_ips", fake)


def _resolver_returning(ip_by_host: dict[str, str]) -> MagicMock:
    """Fake dnspython resolver: answers A/AAAA from a dict, NXDOMAIN otherwise."""

    def _resolve(hostname: str, rdtype: str):
        ip = ip_by_host.get(hostname)
        if ip is None:
            raise dns.resolver.NXDOMAIN()
        rdata = MagicMock()
        rdata.to_text.return_value = ip
        return [rdata]

    resolver = MagicMock()
    resolver.resolve.side_effect = _resolve
    return resolver


class TestIPAndSSRFValidation:
    """Test suite for IP filtering, IPv4-mapped IPv6 unwrapping, and SSRF guard."""

    @pytest.mark.parametrize(
        "public_ip",
        [
            "93.184.216.34",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:93.184.216.34",  # IPv4-mapped IPv6 pointing to public IP
            "64:ff9b::808:808",  # NAT64 embedding 8.8.8.8
            "2002:808:808::1",  # 6to4 embedding 8.8.8.8
        ],
    )
    def test_safe_public_ips_allowed(self, public_ip: str):
        """Verify globally routable public IPs are accepted."""
        assert is_safe_public_ip(public_ip) is True

    @pytest.mark.parametrize(
        "private_or_restricted_ip",
        [
            "127.0.0.1",              # Loopback
            "::1",                    # IPv6 loopback
            "10.0.0.1",               # RFC 1918 Private
            "172.16.0.1",             # RFC 1918 Private
            "192.168.1.1",            # RFC 1918 Private
            "169.254.169.254",        # Link-local (Cloud metadata)
            "fe80::1",                # IPv6 link-local
            "100.64.0.1",             # CGNAT (Specifically required in tweak 2)
            "0.0.0.0",                # Unspecified (Specifically required in tweak 2)
            "::ffff:127.0.0.1",       # IPv4-mapped IPv6 loopback (Specifically required in tweak 2)
            "224.0.0.1",              # Multicast
            "ff02::1",                # IPv6 multicast
            "invalid_ip",             # Malformed string
            "::7f00:1",               # Deprecated IPv4-compatible form of 127.0.0.1
            "64:ff9b::7f00:1",        # NAT64 embedding 127.0.0.1
            "64:ff9b::a9fe:a9fe",     # NAT64 embedding 169.254.169.254 (metadata)
            "2002:7f00:1::1",         # 6to4 embedding 127.0.0.1
            "fec0::1",                # Deprecated IPv6 site-local
        ],
    )
    def test_private_and_restricted_ips_rejected(self, private_or_restricted_ip: str):
        """Verify private, loopback, CGNAT, link-local, and multicast IPs are rejected."""
        assert is_safe_public_ip(private_or_restricted_ip) is False

    def test_check_host_for_ssrf_rejects_private(self):
        """Verify check_host_for_ssrf flags hosts resolving to private IPs."""
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "10.0.0.5"
        mock_resolver.resolve.return_value = [mock_rdata]

        safe, reason = check_host_for_ssrf("internal.example.com", resolver=mock_resolver)
        assert safe is False
        assert "non-public/private IP: 10.0.0.5" in (reason or "")


class TestRedirectScopeControl:
    """Test suite for scheme, port, and domain validation on redirects."""

    def test_in_scope_redirects(self):
        """Verify in-scope same-domain or subdomain redirects on default ports."""
        assert is_redirect_in_scope("https://example.com/", "example.com") is True
        assert is_redirect_in_scope("http://sub.example.com/", "example.com") is True
        assert is_redirect_in_scope("https://api.corp.example.com:443/login", "example.com") is True
        assert is_redirect_in_scope("http://example.com:80/path", "example.com") is True

    @pytest.mark.parametrize(
        "out_of_scope_url",
        [
            "https://evil.com/",
            "http://notexample.com/",
            "https://example.com:8443/",       # Non-default HTTPS port
            "http://example.com:8080/",        # Non-default HTTP port
            "ftp://example.com/",              # Non-HTTP scheme
            "http://192.168.1.1/",             # IP target
            "https://93.184.216.34/",          # Public IP target (only hostnames permitted)
        ],
    )
    def test_out_of_scope_redirects(self, out_of_scope_url: str):
        """Verify non-default ports, external domains, and IP targets are marked out-of-scope."""
        assert is_redirect_in_scope(out_of_scope_url, "example.com") is False


class TestTitleExtraction:
    """Test suite for HTML <title> tag extraction, encoding, and sanitization."""

    def test_normal_title(self):
        """Verify standard title extraction from text/html."""
        html = b"<html><head><title>My Homepage</title></head><body></body></html>"
        title = extract_title(html, "text/html; charset=utf-8")
        assert title == "My Homepage"

    def test_uppercase_title_tag(self):
        """Verify case-insensitive <TITLE> tag extraction."""
        html = b"<html><head><TITLE>Capitalized Site</TITLE></head></html>"
        title = extract_title(html, "text/html")
        assert title == "Capitalized Site"

    def test_title_with_whitespace_and_newlines(self):
        """Verify excess whitespace and newlines are collapsed to single spaces."""
        html = b"<html><title>  \n  Welcome \n to   \t my   world!  \n</title></html>"
        title = extract_title(html, "text/html")
        assert title == "Welcome to my world!"

    def test_missing_or_empty_title(self):
        """Verify missing or empty title returns None."""
        assert extract_title(b"<html><body>No title here</body></html>", "text/html") is None
        assert extract_title(b"<html><title>   </title></html>", "text/html") is None

    def test_non_html_content_type_returns_none(self):
        """Verify title is ignored when Content-Type is not text/html."""
        json_bytes = b'{"title": "API Status OK"}'
        assert extract_title(json_bytes, "application/json") is None

    def test_very_long_title_truncated_to_200(self):
        """Verify titles exceeding 200 characters are safely truncated."""
        long_text = "A" * 300
        html = f"<html><title>{long_text}</title></html>".encode()
        title = extract_title(html, "text/html")
        assert title is not None
        assert len(title) == 200
        assert title == "A" * 200


class TestStreamingBodyLimit:
    """Test suite for the 64 KB streaming limit."""

    def test_stream_caps_at_64kb(self):
        """Verify response body streaming terminates at exactly 64 KB."""
        # 100 KB payload
        chunk = b"X" * 1024
        stream_chunks = [chunk for _ in range(100)]

        response_mock = MagicMock(spec=httpx.Response)
        response_mock.iter_bytes.return_value = iter(stream_chunks)

        body = _stream_and_read_body(response_mock, deadline=time.perf_counter() + 10.0)
        assert len(body) == MAX_BODY_BYTES


class TestProberNetworkingAndTLS:
    """Test suite for active probing, real TLS error shapes, and redirect flows."""

    def test_https_success(self):
        """Verify successful HTTPS probe sets tls_valid = True and extracts title."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Server": "nginx/1.24"},
                html="<html><title>Secure Portal</title></html>",
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://api.example.com/", "example.com", client)

        assert result.reachable is True
        assert result.status_code == 200
        assert result.tls_valid is True
        assert result.title == "Secure Portal"
        assert result.server == "nginx/1.24"

    def test_real_tls_verification_error_and_retry(self):
        """Verify real TLS verification error chain triggers verify=False retry."""
        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            # First attempt fails with real SSLCertVerificationError chained inside ConnectError
            if attempt_count == 1:
                cert_err = ssl.SSLCertVerificationError(
                    "certificate verify failed: certificate has expired"
                )
                connect_err = httpx.ConnectError(
                    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
                )
                connect_err.__cause__ = cert_err
                raise connect_err
            # Second attempt (with verify=False) succeeds
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                html="<html><title>Expired Cert Site</title></html>",
            )

        mock_transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=mock_transport)

        # Patch httpx.Client so the retry client also uses mock_transport
        with patch("asm.prober.httpx.Client", return_value=client):
            result = probe_url("https://expired.example.com/", "example.com", client)

        assert result.reachable is True
        assert result.status_code == 200
        assert result.tls_valid is False
        assert result.title == "Expired Cert Site"
        assert result.error_type == ProbeErrorType.TLS_ERROR.value
        assert "Certificate verification failed" in (result.error_message or "")

    def test_out_of_scope_redirect_reachable(self):
        """Verify out-of-scope redirect marks host reachable and records status code."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                302,
                headers={"Location": "https://external-auth.com/login"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://sso.example.com/", "example.com", client)

        assert result.reachable is True
        assert result.status_code == 302
        assert len(result.redirect_chain) == 1
        assert result.redirect_chain[0].out_of_scope is True
        assert result.redirect_chain[0].url == "https://external-auth.com/login"

    def test_redirect_missing_location_header(self):
        """Verify redirect with missing Location header is treated as a final response."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                301,
                headers={"Content-Type": "text/html"},
                html="<html><title>Moved Permanently</title></html>",
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://legacy.example.com/", "example.com", client)

        assert result.reachable is True
        assert result.status_code == 301
        assert result.title == "Moved Permanently"
        assert len(result.redirect_chain) == 0

    def test_too_many_redirects_marks_reachable(self):
        """Verify redirect loop stopping after 5 hops marks reachable with error_type."""
        hop_counter = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal hop_counter
            hop_counter += 1
            return httpx.Response(
                302,
                headers={"Location": f"https://loop.example.com/step/{hop_counter}"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://loop.example.com/", "example.com", client)

        assert result.reachable is True
        assert result.status_code == 302
        assert result.error_type == ProbeErrorType.TOO_MANY_REDIRECTS.value
        assert len(result.redirect_chain) == 6  # Initial request + 5 followed hops = 6 recorded

    def test_total_deadline_exceeded(self):
        """Verify 10s deadline maps to TIMEOUT using mocked time.perf_counter."""
        call_count = 0

        def mock_perf_counter():
            nonlocal call_count
            call_count += 1
            # Advance past the 10s deadline on subsequent calls
            return 100.0 if call_count == 1 else 115.0

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with patch("time.perf_counter", side_effect=mock_perf_counter):
            result = probe_url("https://slow.example.com/", "example.com", client)

        assert result.reachable is False
        assert result.error_type == ProbeErrorType.TIMEOUT.value


class TestProbeHostIntegration:
    """Test suite for probe_host logic: validation, SSRF, and fallback."""

    def test_tampered_untrusted_host_skipped(self):
        """Verify tampered host failing validation or out-of-scope is skipped."""
        res_invalid = probe_host("bad..domain", "example.com")
        assert res_invalid.status == HostProbeStatus.SKIPPED_UNTRUSTED.value

        res_scope = probe_host("attacker.org", "example.com")
        assert res_scope.status == HostProbeStatus.SKIPPED_UNTRUSTED.value

    def test_private_ip_host_skipped(self):
        """Verify host resolving to private IP is skipped as SKIPPED_PRIVATE_IP."""
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "192.168.1.100"
        mock_resolver.resolve.return_value = [mock_rdata]

        res = probe_host("router.example.com", "example.com", resolver=mock_resolver)
        assert res.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
        assert res.live is False

    def test_https_fails_then_http_succeeds(self):
        """Verify HTTPS failing then HTTP succeeding results in live=True."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.scheme == "https":
                raise httpx.ConnectError("Connection refused on port 443")
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                html="<html><title>Plain HTTP Only</title></html>",
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        resolver = _resolver_returning({"web.example.com": "93.184.216.34"})
        res = probe_host("web.example.com", "example.com", resolver=resolver, client=client)

        assert res.status == HostProbeStatus.PROBED.value
        assert res.live is True
        assert res.https is not None and res.https.reachable is False
        assert res.http is not None and res.http.reachable is True
        assert res.preferred_url == "http://web.example.com/"


class TestSSRFFailClosedAndRedirectGuard:
    """P1 hardening: unresolved hosts fail closed; redirect hops are SSRF-checked."""

    def test_check_host_for_ssrf_fails_closed_when_unresolved(self):
        """A host with no A/AAAA answer must NOT be treated as safe."""
        safe, reason = check_host_for_ssrf(
            "ghost.example.com", resolver=_resolver_returning({})
        )
        assert safe is False
        assert (reason or "").startswith(UNRESOLVED_REASON_PREFIX)

    def test_probe_host_unresolved_is_skipped_unresolved(self):
        """Unresolvable hosts are reported as SKIPPED_UNRESOLVED and never contacted."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        res = probe_host(
            "ghost.example.com", "example.com", resolver=_resolver_returning({}), client=client
        )
        assert res.status == HostProbeStatus.SKIPPED_UNRESOLVED.value
        assert calls["n"] == 0

    def test_redirect_to_in_scope_host_with_private_ip_is_not_followed(self):
        """sso.example.com -> meta.example.com (169.254.169.254) must stop before the hop."""
        requested_hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.headers["host"])
            if request.headers["host"] == "sso.example.com":
                return httpx.Response(302, headers={"Location": "https://meta.example.com/"})
            return httpx.Response(200, html="<title>metadata</title>")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        resolver = _resolver_returning(
            {"sso.example.com": "93.184.216.34", "meta.example.com": "169.254.169.254"}
        )
        result = probe_url("https://sso.example.com/", "example.com", client, resolver=resolver)

        assert requested_hosts == ["sso.example.com"]
        assert result.redirect_chain[-1].out_of_scope is True
        assert "SSRF" in (result.error_message or "")
        assert result.title is None

    def test_redirect_to_in_scope_public_host_is_followed(self):
        """A redirect to a different in-scope host with a public IP is still followed."""
        requested_hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.headers["host"])
            if request.headers["host"] == "example.com":
                return httpx.Response(301, headers={"Location": "https://www.example.com/"})
            return httpx.Response(200, html="<title>Home</title>")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        resolver = _resolver_returning(
            {"example.com": "93.184.216.34", "www.example.com": "93.184.216.34"}
        )
        result = probe_url("https://example.com/", "example.com", client, resolver=resolver)

        assert requested_hosts == ["example.com", "www.example.com"]
        assert result.title == "Home"
        assert result.final_url == "https://www.example.com/"

    def test_probe_requests_uncompressed_bodies(self):
        """Accept-Encoding: identity keeps the 64 KB cap meaningful (no decompression bombs)."""
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["accept-encoding"] = request.headers.get("accept-encoding", "")
            return httpx.Response(200)

        transport = httpx.MockTransport(handler)
        resolver = _resolver_returning({"web.example.com": "93.184.216.34"})
        real_client = httpx.Client  # capture before patching (patch replaces httpx.Client)
        with patch(
            "asm.prober.httpx.Client",
            side_effect=lambda **kw: real_client(transport=transport, **kw),
        ):
            probe_host("web.example.com", "example.com", resolver=resolver)

        assert seen["accept-encoding"] == "identity"


class TestDeadlineCoversConnectAndHeaders:
    """v3.6b B-2 (bug h): every request gets timeouts that fit inside the 10 s deadline."""

    def test_each_hop_timeout_fits_remaining_time(self, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr("asm.prober.time.perf_counter", lambda: clock[0])
        seen: list[tuple[float, float, float]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            timeouts = request.extensions["timeout"]
            remaining = (1000.0 + TOTAL_URL_TIMEOUT) - clock[0]
            seen.append((timeouts["connect"], timeouts["read"], remaining))
            clock[0] += 3.0  # each hop takes 3 s of the budget
            hop = len(seen)
            if hop < 3:
                return httpx.Response(302, headers={"Location": f"/step{hop}"})
            return httpx.Response(200, html="<title>done</title>")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://api.example.com/", "example.com", client)

        assert result.status_code == 200
        assert len(seen) == 3
        for connect, read, remaining in seen:
            # Connect and header read together never exceed the time that is left.
            assert connect + read <= remaining + 1e-9
            assert connect <= CONNECT_TIMEOUT
        assert seen[0][1] > seen[1][1] > seen[2][1]  # budgets shrink hop by hop

    def test_no_request_is_sent_after_the_deadline(self, monkeypatch):
        clock = [0.0]
        monkeypatch.setattr("asm.prober.time.perf_counter", lambda: clock[0])
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url)
            clock[0] += TOTAL_URL_TIMEOUT + 1  # the first hop eats the whole budget
            return httpx.Response(302, headers={"Location": "/next"})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = probe_url("https://api.example.com/", "example.com", client)

        assert len(calls) == 1
        assert result.reachable is False
