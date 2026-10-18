"""Unit tests for active HTTP/HTTPS host prober and security controls."""

from __future__ import annotations

import gzip
import ssl
import time
import zlib
from unittest.mock import MagicMock, patch

import dns.resolver
import httpx
import pytest

from asm.models import HostProbeStatus, ProbeErrorType
from asm.prober import (
    CONNECT_TIMEOUT,
     MAX_BODY_BYTES,
    TOTAL_URL_TIMEOUT,
    DeadlineExceeded,
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
            "168.63.129.16",          # Azure WireServer / platform DNS (public-looking)
            "::ffff:168.63.129.16",   # IPv4-mapped Azure WireServer
            "64:ff9b::a83f:8110",     # NAT64 embedding 168.63.129.16
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
        """Verify response body streaming terminates at exactly 64 KB and closes stream."""
        chunk = b"X" * 1024

        class HundredKilobyteStream(httpx.SyncByteStream):
            def __init__(self) -> None:
                self.closed = False
                self.chunks_emitted = 0

            def __iter__(self):
                for _ in range(100):
                    self.chunks_emitted += 1
                    yield chunk

            def close(self) -> None:
                self.closed = True

        stream = HundredKilobyteStream()
        response = httpx.Response(200, stream=stream)

        body = _stream_and_read_body(response, deadline=time.perf_counter() + 10.0)
        assert len(body) == MAX_BODY_BYTES
        assert stream.chunks_emitted == 64
        assert stream.closed is True
        assert response.is_closed is True


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

    def test_host_resolving_to_azure_wireserver_is_never_contacted(self):
        """168.63.129.16 passes is_global but is the Azure WireServer: refuse before connecting."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        resolver = _resolver_returning({"wire.example.com": "168.63.129.16"})
        safe, reason = check_host_for_ssrf("wire.example.com", resolver=resolver)
        res = probe_host("wire.example.com", "example.com", resolver=resolver, client=client)

        assert safe is False and "168.63.129.16" in (reason or "")
        assert res.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
        assert calls["n"] == 0

    def test_azure_block_is_exactly_one_address(self):
        """The neighbours of 168.63.129.16 are ordinary public addresses."""
        assert is_safe_public_ip("168.63.129.15") is True
        assert is_safe_public_ip("168.63.129.17") is True

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


class TestContentEncodingAndBoundedBodyPolicy:
    """Regressions for bounded response-body policy and Content-Encoding handling."""

    def test_gzip_response_prevents_automatic_decompression_before_body_limit(self):
        """A small gzip payload expanding past MAX_BODY_BYTES must not be decompressed."""
        uncompressed_html = (
            b"<html><head><title>Compressed Secret</title></head><body>"
            + (b"A" * (MAX_BODY_BYTES + 16384))
            + b"</body></html>"
        )
        compressed_payload = gzip.compress(uncompressed_html)
        assert len(compressed_payload) < 512

        decompressed_bytes = 0
        stream_chunks_read = 0

        class RecordingStream(httpx.SyncByteStream):
            def __init__(self) -> None:
                self.closed = False

            def __iter__(self):
                nonlocal stream_chunks_read
                stream_chunks_read += 1
                yield compressed_payload

            def close(self) -> None:
                self.closed = True

        stream = RecordingStream()
        response = httpx.Response(
            status_code=200,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Content-Encoding": "gzip",
                "Content-Length": str(len(compressed_payload)),
            },
            stream=stream,
        )

        decoder = response._get_content_decoder()
        orig_decode = decoder.decode

        def tracking_decode(data: bytes) -> bytes:
            nonlocal decompressed_bytes
            out = orig_decode(data)
            decompressed_bytes += len(out)
            return out

        decoder.decode = tracking_decode  # type: ignore[method-assign]

        body = _stream_and_read_body(response, deadline=time.perf_counter() + 10.0)
        assert body == b""
        assert decompressed_bytes == 0
        assert stream_chunks_read == 0
        assert stream.closed is True
        assert response.is_closed is True

    @pytest.mark.parametrize(
        "content_encoding",
        [
            "gzip",
            "GZIP",
            "x-gzip",
            "deflate",
            "br",
            "zstd",
            "identity, gzip",
            "gzip, deflate",
            "custom-encoding",
        ],
    )
    def test_non_identity_encoding_preserves_reachability_and_headers_without_parsing_html(
        self, content_encoding: str
    ):
        """Unsupported Content-Encoding keeps reachable=True/headers, title=None, and closes."""
        raw_html_or_compressed = (
            gzip.compress(b"<html><title>Gzip Title</title></html>" + b"X" * 70000)
            if "gzip" in content_encoding.lower()
            else zlib.compress(b"<html><title>Deflate Title</title></html>" + b"X" * 70000)
            if "deflate" in content_encoding.lower()
            else b"<html><title>Raw Misclassified HTML</title></html>"
        )
        tracked_responses: list[httpx.Response] = []
        sent_accept_encoding: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent_accept_encoding.append(request.headers.get("accept-encoding", ""))
            resp = httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Encoding": content_encoding,
                    "Server": "nginx/1.26",
                    "X-Powered-By": "Express",
                },
                stream=httpx.ByteStream(raw_html_or_compressed),
            )
            tracked_responses.append(resp)
            return resp

        transport = httpx.MockTransport(handler)
        resolver = _resolver_returning({"app.example.com": "93.184.216.34"})
        real_client = httpx.Client
        with patch(
            "asm.prober.httpx.Client",
            side_effect=lambda **kw: real_client(transport=transport, **kw),
        ):
            host_res = probe_host("app.example.com", "example.com", resolver=resolver)

        assert sent_accept_encoding == ["identity", "identity"]
        assert host_res.status == HostProbeStatus.PROBED.value
        assert host_res.live is True
        assert host_res.preferred_url == "https://app.example.com/"
        for url_res in (host_res.https, host_res.http):
            assert url_res is not None
            assert url_res.reachable is True
            assert url_res.status_code == 200
            assert url_res.title is None
            assert url_res.server == "nginx/1.26"
            assert url_res.x_powered_by == "Express"
            assert url_res.content_type == "text/html; charset=utf-8"
            assert url_res.error_type is None
        assert len(tracked_responses) == 2
        assert all(r.is_closed for r in tracked_responses)

    @pytest.mark.parametrize(
        "repeated_headers",
        [
            [("Content-Encoding", "identity"), ("Content-Encoding", "gzip")],
            [("Content-Encoding", "gzip"), ("Content-Encoding", "identity")],
            [("Content-Encoding", ""), ("Content-Encoding", "br")],
            [("Content-Encoding", "identity, deflate"), ("Content-Encoding", "gzip")],
        ],
    )
    def test_repeated_content_encoding_headers_with_non_identity_token_rejected(
        self, repeated_headers: list[tuple[str, str]]
    ):
        """Repeated Content-Encoding headers containing any non-identity token are rejected."""
        tracked_response: httpx.Response | None = None
        payload = gzip.compress(b"<html><title>Hidden Title</title></html>" + b"X" * 70000)

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(
                200,
                headers=[("Content-Type", "text/html; charset=utf-8"), *repeated_headers],
                stream=httpx.ByteStream(payload),
            )
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        res = probe_url("https://multi.example.com/", "example.com", client)

        assert res.reachable is True
        assert res.status_code == 200
        assert res.title is None
        assert tracked_response is not None and tracked_response.is_closed is True

    @pytest.mark.parametrize(
        "identity_headers",
        [
            [],
            [("Content-Encoding", "")],
            [("Content-Encoding", "identity")],
            [("Content-Encoding", "IDENTITY")],
            [("Content-Encoding", "identity, identity")],
            [("Content-Encoding", "identity"), ("Content-Encoding", "IDENTITY")],
            [("Content-Encoding", "identity"), ("Content-Encoding", "")],
        ],
    )
    def test_identity_and_omitted_encoding_extracts_title_and_closes(
        self, identity_headers: list[tuple[str, str]]
    ):
        """Omitted or identity Content-Encoding (including repeated headers) extracts title."""
        tracked_response: httpx.Response | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            headers = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Server", "Caddy"),
                *identity_headers,
            ]
            tracked_response = httpx.Response(
                200,
                headers=headers,
                stream=httpx.ByteStream(
                    b"<html><head><title>Identity Dashboard</title></head></html>"
                ),
            )
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        res = probe_url("https://portal.example.com/", "example.com", client)

        assert res.reachable is True
        assert res.status_code == 200
        assert res.title == "Identity Dashboard"
        assert tracked_response is not None and tracked_response.is_closed is True

    def test_real_streaming_body_limit_stops_at_64kb_and_closes_stream(self):
        """Real httpx.Response streaming stops after MAX_BODY_BYTES and closes the stream."""
        chunks_yielded = 0

        class LargeUncompressedStream(httpx.SyncByteStream):
            def __init__(self) -> None:
                self.closed = False

            def __iter__(self):
                nonlocal chunks_yielded
                for i in range(100):  # 100 * 1024 = 100 KB
                    chunks_yielded += 1
                    if i == 0:
                        yield b"<html><title>Early Title</title>" + b"B" * (1024 - 32)
                    else:
                        yield b"B" * 1024

            def close(self) -> None:
                self.closed = True

        stream = LargeUncompressedStream()
        response = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            stream=stream,
        )

        body = _stream_and_read_body(response, deadline=time.perf_counter() + 10.0)
        assert len(body) == MAX_BODY_BYTES
        assert chunks_yielded == 64
        assert stream.closed is True
        assert response.is_closed is True
        assert extract_title(body, "text/html") == "Early Title"

    def test_single_oversized_chunk_retains_at_most_64kb_and_closes(self):
        """A single transport chunk larger than 64 KB is sliced to MAX_BODY_BYTES and closed."""
        stream_closed = False

        class SingleGiantChunkStream(httpx.SyncByteStream):
            def __iter__(self):
                prefix = b"<html><title>Single Chunk</title></html>"
                yield prefix + (b"Z" * (MAX_BODY_BYTES + 20000))

            def close(self) -> None:
                nonlocal stream_closed
                stream_closed = True

        response = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            stream=SingleGiantChunkStream(),
        )
        body = _stream_and_read_body(response, deadline=time.perf_counter() + 10.0)
        assert len(body) == MAX_BODY_BYTES
        assert stream_closed is True
        assert response.is_closed is True

    def test_deadline_exceeded_mid_stream_closes_response(self):
        """Raising DeadlineExceeded while streaming still closes the response."""
        stream_closed = False

        class SlowStream(httpx.SyncByteStream):
            def __iter__(self):
                yield b"chunk-1"
                yield b"chunk-2"

            def close(self) -> None:
                nonlocal stream_closed
                stream_closed = True

        response = httpx.Response(200, stream=SlowStream())
        with pytest.raises(DeadlineExceeded):
            _stream_and_read_body(response, deadline=time.perf_counter() - 1.0)

        assert stream_closed is True
        assert response.is_closed is True

    def test_stream_exception_closes_response(self):
        """Raising a transport error mid-stream still closes the response and stream."""
        stream_closed = False

        class FailingStream(httpx.SyncByteStream):
            def __iter__(self):
                yield b"partial-data"
                raise httpx.ReadError("socket reset mid-body")

            def close(self) -> None:
                nonlocal stream_closed
                stream_closed = True

        response = httpx.Response(200, stream=FailingStream())
        with pytest.raises(httpx.ReadError):
            _stream_and_read_body(response, deadline=time.perf_counter() + 10.0)

        assert stream_closed is True
        assert response.is_closed is True

    def test_already_consumed_response_contract_is_bounded_and_closed(self):
        """Already-consumed responses enforce Content-Encoding, deadline, cap, and closure."""
        oversized_html = (
            b"<html><title>Preloaded Title</title></html>" + b"P" * (MAX_BODY_BYTES + 4096)
        )
        resp_identity = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=oversized_html,
        )
        assert resp_identity.is_stream_consumed is True
        body = _stream_and_read_body(resp_identity, deadline=time.perf_counter() + 10.0)
        assert len(body) == MAX_BODY_BYTES
        assert extract_title(body, "text/html") == "Preloaded Title"
        assert resp_identity.is_closed is True

        resp_encoded = httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Encoding": "br"},
            content=b"<html><title>Should Ignore</title></html>",
        )
        assert resp_encoded.is_stream_consumed is True
        assert _stream_and_read_body(resp_encoded, deadline=time.perf_counter() + 10.0) == b""
        assert resp_encoded.is_closed is True

        resp_expired = httpx.Response(200, text="expired")
        assert resp_expired.is_stream_consumed is True
        with pytest.raises(DeadlineExceeded):
            _stream_and_read_body(resp_expired, deadline=time.perf_counter() - 1.0)
        assert resp_expired.is_closed is True

    def test_compressed_redirect_hop_followed_to_uncompressed_final_response(self):
        """A 302 redirect with gzip is not decompressed, closes, and follows Location."""
        hop_responses: list[httpx.Response] = []
        compressed_redirect_body = gzip.compress(
            b"<html><title>Redirecting</title></html>" + (b"R" * (MAX_BODY_BYTES + 8192))
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                resp = httpx.Response(
                    302,
                    headers={
                        "Location": "https://app.example.com/login",
                        "Content-Encoding": "gzip",
                        "Content-Type": "text/html",
                    },
                    stream=httpx.ByteStream(compressed_redirect_body),
                )
            else:
                resp = httpx.Response(
                    200,
                    headers={"Content-Type": "text/html", "Server": "envoy"},
                    stream=httpx.ByteStream(b"<html><title>Sign In</title></html>"),
                )
            hop_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        res = probe_url("https://app.example.com/", "example.com", client)

        assert res.reachable is True
        assert res.status_code == 200
        assert res.final_url == "https://app.example.com/login"
        assert res.title == "Sign In"
        assert len(res.redirect_chain) == 1
        assert res.redirect_chain[0].status_code == 302
        assert len(hop_responses) == 2
        assert all(r.is_closed for r in hop_responses)

    @pytest.mark.parametrize("status_code", [301, 404, 500])
    def test_compressed_error_and_redirect_without_location_preserve_status_and_close(
        self, status_code: int
    ):
        """Compressed 404/500 and 301-without-Location preserve status/headers and close."""
        tracked_response: httpx.Response | None = None
        compressed_body = gzip.compress(
            b"<html><title>Error Page Title</title></html>" + (b"E" * (MAX_BODY_BYTES + 8192))
        )

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(
                status_code,
                headers={
                    "Content-Type": "text/html",
                    "Content-Encoding": "gzip",
                    "Server": "cloudflare",
                },
                stream=httpx.ByteStream(compressed_body),
            )
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        res = probe_url("https://err.example.com/", "example.com", client)

        assert res.reachable is True
        assert res.status_code == status_code
        assert res.title is None
        assert res.server == "cloudflare"
        assert tracked_response is not None and tracked_response.is_closed is True

    def test_tls_verify_retry_with_compressed_response_preserves_reachability_without_decompression(
        self,
    ):
        """When verify=True fails with cert error and verify=False returns gzip, no decode runs."""
        attempt = 0
        retry_response: httpx.Response | None = None
        compressed_body = gzip.compress(
            b"<html><title>Self Signed Gzip</title></html>" + (b"S" * (MAX_BODY_BYTES + 8192))
        )

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt, retry_response
            attempt += 1
            if attempt == 1:
                cert_err = ssl.SSLCertVerificationError("self-signed certificate")
                conn_err = httpx.ConnectError("TLS verify failed")
                conn_err.__cause__ = cert_err
                raise conn_err
            retry_response = httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Content-Encoding": "gzip",
                    "Server": "Apache",
                },
                stream=httpx.ByteStream(compressed_body),
            )
            return retry_response

        mock_transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=mock_transport)
        with patch("asm.prober.httpx.Client", return_value=client):
            res = probe_url("https://selfsigned.example.com/", "example.com", client)

        assert res.reachable is True
        assert res.tls_valid is False
        assert res.status_code == 200
        assert res.title is None
        assert res.server == "Apache"
        assert res.error_type == ProbeErrorType.TLS_ERROR.value
        assert retry_response is not None and retry_response.is_closed is True
