"""Phase D-1: DNS pinning. Every scanner connection goes to the IP that passed the
SSRF check; the hostname is kept for the Host header, SNI and certificate checks.

The rebinding resolver answers a public IP on the first lookup of a host and the
metadata address afterwards, so any second lookup that reaches a connection shows up
as a request to 169.254.169.254. No real network: HTTP goes through MockTransport or
a local TLS server on 127.0.0.1, and port connects are recorded, not made.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import dns.resolver
import httpx
import pytest

from asm import portscan, scan_common
from asm.headers_inspect import inspect_single_host, run_inspection
from asm.models import HostProbeStatus
from asm.prober import probe_host, probe_url
from asm.scan_common import pick_ip, pin_host, pinned_request, resolve_public_ips
from asm.scoring import evaluate_probe_findings
from asm.tls_inspect import connect_and_inspect_cert_socket
from tests.test_tls_socket import HOST as TLS_HOST
from tests.test_tls_socket import pki  # noqa: F401  (module-scoped fixture)

PUBLIC_IP = "93.184.216.34"
OTHER_PUBLIC_IP = "93.184.216.35"
METADATA_IP = "169.254.169.254"
PUBLIC_V6 = "2606:4700:4700::1111"


class RebindingResolver:
    """Fake dnspython resolver. First A answer per host is public, later ones are
    the metadata IP (a DNS-rebinding attacker). Counts A lookups per host."""

    def __init__(self, first_a: dict[str, str], aaaa: dict[str, str] | None = None) -> None:
        self.first_a = first_a
        self.aaaa = aaaa or {}
        self.a_lookups: dict[str, int] = {}
        self.lifetime = self.timeout = 0

    def resolve(self, hostname: str, rdtype: str):
        if rdtype == "AAAA":
            if hostname not in self.aaaa:
                raise dns.resolver.NoAnswer()
            return [_rdata(self.aaaa[hostname])]
        if hostname not in self.first_a:
            raise dns.resolver.NoAnswer()
        n = self.a_lookups.get(hostname, 0)
        self.a_lookups[hostname] = n + 1
        return [_rdata(self.first_a[hostname] if n == 0 else METADATA_IP)]


def _rdata(ip: str) -> MagicMock:
    rdata = MagicMock()
    rdata.to_text.return_value = ip
    return rdata


def _recording_client(responder) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responder(request)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


# --- helpers ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "ip", "wire", "host", "ext"),
    [
        ("https://a.example.com/", PUBLIC_IP, f"https://{PUBLIC_IP}/", "a.example.com",
         {"sni_hostname": "a.example.com"}),
        ("http://a.example.com", PUBLIC_IP, f"http://{PUBLIC_IP}/", "a.example.com", {}),
        ("https://A.example.com.:8443/p?q=1", PUBLIC_V6, f"https://[{PUBLIC_V6}]:8443/p?q=1",
         "a.example.com:8443", {"sni_hostname": "a.example.com"}),
    ],
)
def test_pinned_request_puts_ip_in_url_and_hostname_in_host_and_sni(url, ip, wire, host, ext):
    wire_url, headers, extensions = pinned_request(url, ip)
    assert wire_url == wire
    assert headers == {"Host": host, "Connection": "close"}
    assert extensions == ext


def test_pick_ip_prefers_ipv4_then_ipv6_when_enabled(monkeypatch):
    assert pick_ip("h", [PUBLIC_V6, PUBLIC_IP]) == (PUBLIC_IP, None)
    monkeypatch.delenv("SCAN_IPV6_ENABLED", raising=False)
    ip, reason = pick_ip("h", [PUBLIC_V6])
    assert ip is None and reason.startswith(scan_common.IPV6_ONLY_REASON_PREFIX)
    monkeypatch.setenv("SCAN_IPV6_ENABLED", "true")
    assert pick_ip("h", [PUBLIC_V6]) == (PUBLIC_V6, None)


def test_mixed_public_and_private_answer_is_refused():
    resolver = RebindingResolver({"mix.example.com": PUBLIC_IP}, {"mix.example.com": "fd00::1"})
    ips, reason = resolve_public_ips("mix.example.com", resolver=resolver)
    assert ips is None and "fd00::1" in reason
    assert pin_host("mix.example.com", {}, resolver=resolver)[0] is None


# --- prober -------------------------------------------------------------------------------


def test_probe_host_resolves_once_and_connects_only_to_the_first_answer():
    resolver = RebindingResolver({"app.example.com": PUBLIC_IP})
    client, seen = _recording_client(lambda r: httpx.Response(200, html="<title>x</title>"))

    res = probe_host("app.example.com", "example.com", resolver=resolver, client=client)

    assert res.status == HostProbeStatus.PROBED.value
    assert [r.url.host for r in seen] == [PUBLIC_IP, PUBLIC_IP]  # https, then http
    assert [r.headers["host"] for r in seen] == ["app.example.com", "app.example.com"]
    assert seen[0].extensions["sni_hostname"] == "app.example.com"
    assert resolver.a_lookups == {"app.example.com": 1}


def test_redirect_to_same_host_reuses_the_pin_without_a_new_lookup():
    resolver = RebindingResolver({"app.example.com": PUBLIC_IP})

    def respond(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/":
            return httpx.Response(302, headers={"Location": "/login"})
        return httpx.Response(200, html="<title>login</title>")

    client, seen = _recording_client(respond)
    result = probe_url("https://app.example.com/", "example.com", client, resolver=resolver)

    assert result.title == "login"
    assert result.final_url == "https://app.example.com/login"
    assert {r.url.host for r in seen} == {PUBLIC_IP}
    assert resolver.a_lookups == {"app.example.com": 1}


def test_redirect_to_new_host_is_pinned_to_its_own_first_answer():
    resolver = RebindingResolver({"example.com": PUBLIC_IP, "www.example.com": OTHER_PUBLIC_IP})

    def respond(r: httpx.Request) -> httpx.Response:
        if r.headers["host"] == "example.com":
            return httpx.Response(301, headers={"Location": "https://www.example.com/"})
        return httpx.Response(200, html="<title>home</title>")

    client, seen = _recording_client(respond)
    result = probe_url("https://example.com/", "example.com", client, resolver=resolver)

    assert result.title == "home"
    assert [(r.url.host, r.headers["host"]) for r in seen] == [
        (PUBLIC_IP, "example.com"),
        (OTHER_PUBLIC_IP, "www.example.com"),
    ]
    assert seen[1].extensions["sni_hostname"] == "www.example.com"
    assert resolver.a_lookups == {"example.com": 1, "www.example.com": 1}


def test_unverified_retry_uses_the_same_pinned_ip():
    resolver = RebindingResolver({"old.example.com": PUBLIC_IP})
    calls = {"n": 0}

    def respond(r: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            err = httpx.ConnectError("certificate verify failed")
            err.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
            raise err
        return httpx.Response(200, html="<title>expired</title>")

    client, seen = _recording_client(respond)
    with patch("asm.prober.httpx.Client", return_value=client):
        res = probe_host("old.example.com", "example.com", resolver=resolver, client=client)

    assert res.https is not None and res.https.tls_valid is False and res.https.reachable
    assert {r.url.host for r in seen} == {PUBLIC_IP}
    assert resolver.a_lookups == {"old.example.com": 1}


# --- real TLS: SNI, Host header and certificate checked against the hostname ----------


@pytest.fixture
def https_server(pki):  # noqa: F811
    """Local HTTPS server with a certificate for TLS_HOST; records SNI and Host."""
    seen = {"sni": [], "host": []}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*pki["leaf"])
    ctx.sni_callback = lambda sock, name, c: seen["sni"].append(name)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(10)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(2)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    for line in data.decode("latin-1").split("\r\n"):
                        if line.lower().startswith("host:"):
                            seen["host"].append(line.split(":", 1)[1].strip())
                    body = b"<title>pinned</title>"
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body
                    )
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], seen
    srv.close()


def test_real_https_request_to_pinned_ip_verifies_the_hostname(pki, https_server):  # noqa: F811
    port, seen = https_server
    client = httpx.Client(verify=ssl.create_default_context(cafile=pki["ca_file"]))

    result = probe_url(
        f"https://{TLS_HOST}:{port}/", TLS_HOST, client, pins={TLS_HOST: "127.0.0.1"}
    )

    assert result.reachable and result.tls_valid is True and result.title == "pinned"
    assert seen["sni"] == [TLS_HOST]
    assert seen["host"] == [f"{TLS_HOST}:{port}"]


def test_real_https_certificate_for_another_name_fails_verification(pki, https_server):  # noqa: F811
    port, seen = https_server
    client = httpx.Client(verify=ssl.create_default_context(cafile=pki["ca_file"]))
    other = "other.example.com"

    result = probe_url(f"https://{other}:{port}/", "example.com", client, pins={other: "127.0.0.1"})

    # The certificate names TLS_HOST, not other.example.com: verification fails, the
    # unverified retry still reaches the server on the same pinned IP.
    assert result.tls_valid is False and result.reachable is True
    assert seen["sni"] == [other, other]


# --- headers_inspect ------------------------------------------------------------------


class _StreamRecorder:
    """Replaces httpx.Client.stream; records (url, headers, extensions)."""

    def __init__(self, responses):
        self.calls: list[tuple[str, dict, dict]] = []
        self.responses = list(responses)

    def __call__(self, method, url, headers=None, extensions=None, **kw):
        self.calls.append((str(url), dict(headers or {}), dict(extensions or {})))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        cm = MagicMock()
        cm.__enter__.return_value = item
        cm.__exit__.return_value = False
        return cm


def _response(headers=None, redirect=False) -> MagicMock:
    resp = MagicMock()
    resp.is_redirect = redirect
    resp.headers = httpx.Headers(headers or {})
    resp.iter_raw.return_value = [b""]
    resp.extensions = {}
    return resp


def _patch_dns(fake_resolver):
    """run_inspection takes no resolver argument: route its lookups to fake_resolver."""
    real = scan_common.resolve_host_ips

    def lookup(host, resolver=None):
        return real(host, resolver=fake_resolver)

    return patch.object(scan_common, "resolve_host_ips", lookup)


def test_inspection_pins_every_step_and_hands_the_ip_to_the_cert_fallback():
    resolver = RebindingResolver({"app.example.com": PUBLIC_IP})
    tls_err = httpx.ConnectError("verify failed")
    tls_err.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
    stream = _StreamRecorder([tls_err, _response({"X-Frame-Options": "DENY"})])
    fallback = MagicMock(return_value=None)

    probe = [{"subdomain": "app.example.com", "status": "PROBED", "https": {"reachable": True}}]
    with (
        _patch_dns(resolver),
        patch("httpx.Client.stream", stream),
        patch("asm.headers_inspect.connect_and_inspect_cert_socket", fallback),
    ):
        report = run_inspection(probe, "example.com", "probe.json")

    assert report.results[0].headers is not None  # step D (unverified GET) ran
    assert [c[0] for c in stream.calls] == [f"https://{PUBLIC_IP}/"] * 2  # steps A and D
    assert all(c[1]["Host"] == "app.example.com" for c in stream.calls)
    assert all(c[2] == {"sni_hostname": "app.example.com"} for c in stream.calls)
    assert fallback.call_args.kwargs.get("ip") == PUBLIC_IP  # step C, no own lookup
    assert resolver.a_lookups == {"app.example.com": 1}


def test_inspection_redirect_hop_is_pinned_once():
    resolver = RebindingResolver({"example.com": PUBLIC_IP, "www.example.com": OTHER_PUBLIC_IP})
    stream = _StreamRecorder([
        _response({"location": "https://www.example.com/"}, redirect=True),
        _response(),
    ])
    with (
        _patch_dns(resolver),
        patch("httpx.Client.stream", stream),
        patch("asm.headers_inspect.connect_and_inspect_cert_socket", return_value=None),
    ):
        inspect_single_host("example.com", "example.com")

    assert [(c[0], c[1]["Host"]) for c in stream.calls] == [
        (f"https://{PUBLIC_IP}/", "example.com"),
        (f"https://{OTHER_PUBLIC_IP}/", "www.example.com"),
    ]
    assert resolver.a_lookups == {"example.com": 1, "www.example.com": 1}


def test_cert_fallback_with_given_ip_does_no_lookup(monkeypatch):
    lookups = MagicMock(side_effect=AssertionError("must not resolve"))
    monkeypatch.setattr(scan_common, "resolve_host_ips", lookups)
    connected: list[tuple[str, int]] = []

    def fake_connect(address, timeout=None, *a, **k):
        connected.append(address)
        raise OSError("refused")

    monkeypatch.setattr("asm.tls_inspect.socket.create_connection", fake_connect)
    assert connect_and_inspect_cert_socket("app.example.com", ip=PUBLIC_IP, timeout=1) is None
    assert connected == [(PUBLIC_IP, 443)]
    lookups.assert_not_called()


# --- portscan ---------------------------------------------------------------------------


def test_portscan_resolves_once_and_connects_every_port_to_the_pinned_ip():
    resolver = RebindingResolver({"app.example.com": PUBLIC_IP})
    targets: list[str] = []

    async def fake_open(host, port):
        targets.append(host)
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=fake_open):
        res = asyncio.run(
            portscan.scan_host_ports(
                "app.example.com", "example.com", asyncio.Semaphore(1), resolver=resolver
            )
        )

    assert res.status == HostProbeStatus.PROBED.value
    assert targets == [PUBLIC_IP] * len(portscan.DEFAULT_PORTS)
    assert resolver.a_lookups == {"app.example.com": 1}


# --- IPv6-only hosts while IPv6 scanning is off (D11/D12) -------------------------------


@pytest.fixture
def v6_only(monkeypatch):
    monkeypatch.delenv("SCAN_IPV6_ENABLED", raising=False)
    return RebindingResolver({}, {"v6.example.com": PUBLIC_V6})


def test_ipv6_only_host_is_skipped_by_prober_not_reported_down(v6_only):
    client, seen = _recording_client(lambda r: httpx.Response(200))
    res = probe_host("v6.example.com", "example.com", resolver=v6_only, client=client)

    assert res.status == HostProbeStatus.SKIPPED_IPV6_ONLY.value
    assert res.skip_reason.startswith("IPv6-only host")
    assert res.https is None and res.http is None and seen == []
    # A skipped host yields no findings (no "unreachable"/"down" finding).
    assert evaluate_probe_findings([res.to_dict()]).get("v6.example.com", []) == []


def test_ipv6_only_host_is_skipped_by_portscan(v6_only):
    with patch("asyncio.open_connection") as opened:
        res = asyncio.run(
            portscan.scan_host_ports(
                "v6.example.com", "example.com", asyncio.Semaphore(1), resolver=v6_only
            )
        )
    assert res.status == HostProbeStatus.SKIPPED_IPV6_ONLY.value
    assert res.open_ports == [] and res.filtered_ports == []
    opened.assert_not_called()


def test_ipv6_only_host_is_skipped_by_inspection(v6_only):
    probe = [{"subdomain": "v6.example.com", "status": "PROBED", "https": {"reachable": True}}]
    with _patch_dns(v6_only), patch("httpx.Client.stream") as stream:
        report = run_inspection(probe, "example.com", "probe.json")

    assert report.results[0].status == HostProbeStatus.SKIPPED_IPV6_ONLY.value
    assert report.counts["skipped_private_ip"] == 0
    assert report.counts["skipped_unresolved"] == 0
    stream.assert_not_called()


def test_ipv6_host_is_probed_on_its_ipv6_address_when_enabled(monkeypatch):
    monkeypatch.setenv("SCAN_IPV6_ENABLED", "true")
    resolver = RebindingResolver({}, {"v6.example.com": PUBLIC_V6})
    client, seen = _recording_client(lambda r: httpx.Response(200))

    res = probe_host("v6.example.com", "example.com", resolver=resolver, client=client)

    assert res.status == HostProbeStatus.PROBED.value
    assert {r.url.host for r in seen} == {PUBLIC_V6}
    assert {r.headers["host"] for r in seen} == {"v6.example.com"}


@pytest.mark.parametrize("blocked_ip", ["127.0.0.1", METADATA_IP, "10.0.0.1"])
def test_probe_redirect_to_private_host_is_never_contacted(blocked_ip: str) -> None:
    """An in-scope name does not authorize a redirect into a private network."""
    resolver = RebindingResolver({"example.com": PUBLIC_IP, "internal.example.com": blocked_ip})
    destination = "https://internal.example.com/"
    client, seen = _recording_client(
        lambda request: httpx.Response(302, headers={"Location": destination})
    )
    with client:
        result = probe_url("https://example.com/", "example.com", client, resolver=resolver)

    assert [request.url.host for request in seen] == [PUBLIC_IP]
    assert resolver.a_lookups == {"example.com": 1, "internal.example.com": 1}
    assert result.final_url == "https://example.com/"
    assert result.redirect_chain[-1].url == destination
    assert "SSRF guard" in result.error_message


@pytest.mark.parametrize("blocked_ip", ["127.0.0.1", METADATA_IP, "10.0.0.1"])
def test_inspection_redirect_to_private_host_is_never_contacted(blocked_ip: str) -> None:
    """Inspection stops at a private redirect and keeps its original certificate pin."""
    resolver = RebindingResolver({"example.com": PUBLIC_IP, "internal.example.com": blocked_ip})
    stream = _StreamRecorder([
        _response({"location": "https://internal.example.com/"}, redirect=True),
    ])
    fallback = MagicMock(return_value=None)
    with (
        _patch_dns(resolver),
        patch("httpx.Client.stream", stream),
        patch("asm.headers_inspect.connect_and_inspect_cert_socket", fallback),
    ):
        result = inspect_single_host("example.com", "example.com")

    assert [call[0] for call in stream.calls] == [f"https://{PUBLIC_IP}/"]
    assert resolver.a_lookups == {"example.com": 1, "internal.example.com": 1}
    assert fallback.call_args.kwargs.get("ip") == PUBLIC_IP
    assert result.headers is not None
