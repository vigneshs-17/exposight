"""Active HTTP/HTTPS host prober module for Exposight."""

from __future__ import annotations

import ipaddress
import logging
import re
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from typing import Any

import dns.resolver
import httpx

from asm.models import (
    HostProbeResult,
    HostProbeStatus,
    ProbeErrorType,
    RedirectHop,
    UrlProbeResult,
)
from asm.scan_common import (
    check_host_for_ssrf,
    is_safe_public_ip,
    pin_host,
    pinned_request,
    skip_status_for,
    validate_host_and_scope,
)

__all__ = [
    "check_host_for_ssrf",
    "is_safe_public_ip",
    "probe_host",
    "probe_hosts_concurrently",
    "probe_url",
    "validate_host_and_scope",
]

logger = logging.getLogger(__name__)

USER_AGENT = "Exposight/0.1 (+https://github.com/vigneshs-17/exposight)"
CONNECT_TIMEOUT = 5.0
TOTAL_URL_TIMEOUT = 10.0
MAX_REDIRECT_HOPS = 5
MAX_BODY_BYTES = 64 * 1024  # 64 KB body streaming limit
MAX_TITLE_LENGTH = 200
DEFAULT_MAX_WORKERS = 10
# Ask for uncompressed bodies so the 64 KB cap bounds memory (no decompression blow-up).
REQUEST_HEADERS = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}


class DeadlineExceeded(Exception):
    """Raised when the 10-second end-to-end deadline for probing a URL is exceeded."""


def hop_timeout(deadline: float, connect_cap: float = CONNECT_TIMEOUT) -> httpx.Timeout:
    """Per-request timeout that keeps connect + response headers within the deadline.

    httpx timeouts apply to each network operation separately, so a request built
    with the client's fixed 10 s timeout could connect for 5 s and then wait 10 s
    for headers, on every redirect hop. Here the time left is split in half:
    connecting (at most CONNECT_TIMEOUT) and reading the headers each get half,
    so together they cannot pass the deadline. Body reads are also checked against
    the deadline between chunks; one chunk read can still overrun it by at most
    half of the time that was left (worst case 1.5 x TOTAL_URL_TIMEOUT overall).

    Also used by headers_inspect.inspect_single_host for the same reason.

    Raises:
        DeadlineExceeded: If no time is left.
    """
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise DeadlineExceeded("10s total deadline exceeded before request dispatch")
    half = remaining / 2
    return httpx.Timeout(half, connect=min(connect_cap, half))


def _find_exception_in_chain(
    exc: BaseException | None,
    target_type: type[BaseException],
) -> BaseException | None:
    """Walk an exception's __cause__ and __context__ chain looking for a target type.

    In httpx, TLS and certificate verification errors are wrapped inside
    httpx.ConnectError. Walking the chain allows us to pinpoint the underlying cause.
    """
    visited: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in visited:
        if isinstance(current, target_type):
            return current
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def is_tls_cert_verification_error(exc: BaseException) -> bool:
    """Return True if the exception chain contains ssl.SSLCertVerificationError."""
    return _find_exception_in_chain(exc, ssl.SSLCertVerificationError) is not None


def is_general_tls_error(exc: BaseException) -> bool:
    """Return True if the exception chain contains any ssl.SSLError."""
    return _find_exception_in_chain(exc, ssl.SSLError) is not None




def is_redirect_in_scope(target_url: str, base_domain: str) -> bool:
    """Verify that a redirect target conforms to scheme, port, and domain scope rules.

    Rules:
    - Scheme must be 'http' or 'https'.
    - Port must be default: 80 for HTTP, 443 for HTTPS (either implicit or explicit).
      Any non-default port (e.g. 8080, 8443) is considered out-of-scope.
    - Host must equal base_domain or end with '.<base_domain>'.
    - Host must not be an IP address.

    Args:
        target_url: The absolute destination URL of the redirect.
        base_domain: The authorized target domain (e.g. 'example.com').

    Returns:
        True if redirect is in-scope, False otherwise.
    """
    try:
        parsed = urllib.parse.urlsplit(target_url)
    except Exception:
        return False

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False

    # Check port constraints: only default ports allowed
    port = parsed.port
    if scheme == "http" and port is not None and port != 80:
        return False
    if scheme == "https" and port is not None and port != 443:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False
    hostname = hostname.lower().rstrip(".")

    # Reject IP addresses as redirect targets
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass

    normalized_base = base_domain.lower().rstrip(".")
    if hostname == normalized_base or hostname.endswith(f".{normalized_base}"):
        return True

    return False


class _TitleExtractor(HTMLParser):
    """HTML parser to safely extract text from the <title> tag."""

    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_chunks.append(data)


def extract_title(html_bytes: bytes, content_type: str | None) -> str | None:
    """Extract and sanitize the <title> from HTML response bytes.

    Only extracts when Content-Type indicates text/html. Decodes using the charset
    specified in Content-Type (fallback to utf-8) with errors='replace'.
    Trims whitespace and limits output to at most 200 characters.

    Args:
        html_bytes: Raw bytes read from response body (up to 64 KB).
        content_type: Content-Type response header value.

    Returns:
        Sanitized title string, or None if missing, non-HTML, or empty.
    """
    if not content_type or "text/html" not in content_type.lower():
        return None

    # Detect charset from Content-Type header
    encoding = "utf-8"
    match = re.search(r"charset=([a-zA-Z0-9_-]+)", content_type, re.IGNORECASE)
    if match:
        encoding = match.group(1).strip()

    try:
        html_text = html_bytes.decode(encoding, errors="replace")
    except Exception:
        html_text = html_bytes.decode("utf-8", errors="replace")

    parser = _TitleExtractor()
    try:
        parser.feed(html_text)
    except Exception:
        return None

    raw_title = "".join(parser.title_chunks)
    # Collapse multiple whitespaces/newlines into a single space
    cleaned_title = " ".join(raw_title.split()).strip()

    if not cleaned_title:
        return None

    if len(cleaned_title) > MAX_TITLE_LENGTH:
        cleaned_title = cleaned_title[:MAX_TITLE_LENGTH]

    return cleaned_title


def _stream_and_read_body(
    response: httpx.Response,
    deadline: float,
) -> bytes:
    """Stream and read at most 64 KB of the response body while enforcing the deadline.

    Args:
        response: Open streaming httpx Response.
        deadline: Monotonic deadline timestamp.

    Returns:
        Bytes read (up to 64 KB).

    Raises:
        DeadlineExceeded: If deadline is passed during body read.
    """
    body = bytearray()
    for chunk in response.iter_bytes(chunk_size=4096):
        if time.perf_counter() > deadline:
            raise DeadlineExceeded("10s deadline exceeded while reading response body")
        body.extend(chunk)
        if len(body) >= MAX_BODY_BYTES:
            break
    return bytes(body[:MAX_BODY_BYTES])


def _execute_single_url_probe(
    target_url: str,
    base_domain: str,
    client: httpx.Client,
    deadline: float,
    resolver: dns.resolver.Resolver | None = None,
    pins: dict[str, str] | None = None,
) -> UrlProbeResult:
    """Perform HTTP probe with manual redirect following and deadline enforcement.

    Follows up to 5 in-scope redirects manually. Records status code and reachability
    for all HTTP responses (including out-of-scope redirects and too many redirects).

    Args:
        target_url: URL to probe.
        base_domain: Root domain for scope checking.
        client: Pre-configured httpx.Client instance.
        deadline: Monotonic deadline timestamp.
        pins: hostname -> validated IP for this host's probe (see pin_host). Every
            request connects to the pinned IP; URLs, scope checks and results keep
            the hostname.

    Returns:
        UrlProbeResult detailing outcome.
    """
    pins = {} if pins is None else pins
    current_url = target_url
    redirect_chain: list[RedirectHop] = []
    follow_count = 0

    while True:
        ip, pin_reason = pin_host(
            urllib.parse.urlsplit(current_url).hostname or "", pins, resolver=resolver
        )
        if ip is None:
            # Only reachable for the first URL of a direct probe_url call: probe_host
            # pins the host first, and redirect hops are pinned before they are followed.
            return UrlProbeResult(
                url=target_url,
                reachable=False,
                error_type=ProbeErrorType.OTHER.value,
                error_message=f"Not contacted (SSRF guard): {pin_reason}",
            )
        wire_url, pin_headers, extensions = pinned_request(current_url, ip)
        timeout = hop_timeout(deadline)
        start_time = time.perf_counter()

        with client.stream(
            "GET",
            wire_url,
            headers=pin_headers,
            extensions=extensions,
            follow_redirects=False,
            timeout=timeout,
        ) as response:
            response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            body_bytes = _stream_and_read_body(response, deadline)

            status_code = response.status_code
            server_hdr = response.headers.get("server")
            x_powered_hdr = response.headers.get("x-powered-by")
            content_type_hdr = response.headers.get("content-type")

            # Check for redirect status codes
            if status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    # Missing Location header -> treat as final response per requirements
                    title = extract_title(body_bytes, content_type_hdr)
                    return UrlProbeResult(
                        url=target_url,
                        reachable=True,
                        status_code=status_code,
                        final_url=current_url,
                        redirect_chain=redirect_chain,
                        title=title,
                        server=server_hdr,
                        x_powered_by=x_powered_hdr,
                        content_type=content_type_hdr,
                        response_time_ms=response_time_ms,
                    )

                next_url = urllib.parse.urljoin(current_url, location)

                # Check if target redirect is in scope (domain, scheme, and port)
                if not is_redirect_in_scope(next_url, base_domain):
                    # Out of scope: record hop, set reachable=True, and stop following
                    redirect_chain.append(
                        RedirectHop(url=next_url, status_code=status_code, out_of_scope=True)
                    )
                    return UrlProbeResult(
                        url=target_url,
                        reachable=True,
                        status_code=status_code,
                        final_url=current_url,
                        redirect_chain=redirect_chain,
                        server=server_hdr,
                        x_powered_by=x_powered_hdr,
                        content_type=content_type_hdr,
                        response_time_ms=response_time_ms,
                    )

                # SSRF: an in-scope hostname may still point at a private/metadata IP.
                # The hop's host is resolved and pinned once, before it is followed.
                hop_ip, hop_reason = pin_host(
                    urllib.parse.urlsplit(next_url).hostname or "", pins, resolver=resolver
                )
                if hop_ip is None:
                    redirect_chain.append(
                        RedirectHop(url=next_url, status_code=status_code, out_of_scope=True)
                    )
                    return UrlProbeResult(
                        url=target_url,
                        reachable=True,
                        status_code=status_code,
                        final_url=current_url,
                        redirect_chain=redirect_chain,
                        server=server_hdr,
                        x_powered_by=x_powered_hdr,
                        content_type=content_type_hdr,
                        response_time_ms=response_time_ms,
                        error_message=f"Redirect not followed (SSRF guard): {hop_reason}",
                    )

                # In-scope redirect: record hop
                redirect_chain.append(
                    RedirectHop(url=next_url, status_code=status_code, out_of_scope=False)
                )
                follow_count += 1

                # If after 5 follows the response is still a redirect -> TOO_MANY_REDIRECTS
                if follow_count > MAX_REDIRECT_HOPS:
                    return UrlProbeResult(
                        url=target_url,
                        reachable=True,
                        status_code=status_code,
                        final_url=current_url,
                        redirect_chain=redirect_chain,
                        server=server_hdr,
                        x_powered_by=x_powered_hdr,
                        content_type=content_type_hdr,
                        response_time_ms=response_time_ms,
                        error_type=ProbeErrorType.TOO_MANY_REDIRECTS.value,
                        error_message=f"Exceeded maximum of {MAX_REDIRECT_HOPS} redirect hops",
                    )

                current_url = next_url
                continue

            # Non-redirect response (e.g. 200, 404, 500)
            title = extract_title(body_bytes, content_type_hdr)
            return UrlProbeResult(
                url=target_url,
                reachable=True,
                status_code=status_code,
                final_url=current_url,
                redirect_chain=redirect_chain,
                title=title,
                server=server_hdr,
                x_powered_by=x_powered_hdr,
                content_type=content_type_hdr,
                response_time_ms=response_time_ms,
            )


def probe_url(
    target_url: str,
    base_domain: str,
    client: httpx.Client,
    resolver: dns.resolver.Resolver | None = None,
    pins: dict[str, str] | None = None,
) -> UrlProbeResult:
    """Probe a single URL with error classification and TLS verification fallback.

    For HTTPS URLs, initial requests verify certificates normally. If certificate
    verification fails (ssl.SSLCertVerificationError), tls_valid is marked False, and
    we retry once using a dedicated client with verify=False ONLY to determine whether
    an HTTP service is active behind the invalid certificate.

    Args:
        target_url: The URL to probe (e.g. 'https://host.example.com/').
        base_domain: Authorized root domain.
        client: Pre-configured httpx.Client instance (with verify=True).
        pins: hostname -> validated IP, shared with the retry so it hits the same IP.

    Returns:
        UrlProbeResult.
    """
    pins = {} if pins is None else pins
    deadline = time.perf_counter() + TOTAL_URL_TIMEOUT
    is_https = target_url.lower().startswith("https://")

    try:
        result = _execute_single_url_probe(
            target_url, base_domain, client, deadline, resolver=resolver, pins=pins
        )
        if is_https and result.reachable:
            result.tls_valid = True
        return result

    except Exception as exc:
        # Check for certificate verification failure
        if is_https and is_tls_cert_verification_error(exc):
            logger.debug(
                "Cert verification failed for %s. Retrying with verify=False: %s",
                target_url,
                exc,
            )
            # Create a separate client with verify=False solely for this retry attempt.
            # Bandit B501 accepted: verification already failed and is reported as
            # tls_valid=False; this request only shows whether a service answers. It goes
            # to the pinned, SSRF-checked IP, sends no credentials, and nothing is trusted.
            retry_client = httpx.Client(
                verify=False,  # reports an invalid certificate, trusts nothing  # nosec B501
                timeout=httpx.Timeout(TOTAL_URL_TIMEOUT, connect=CONNECT_TIMEOUT),
                headers=REQUEST_HEADERS,
            )
            try:
                retry_result = _execute_single_url_probe(
                    target_url, base_domain, retry_client, deadline, resolver=resolver, pins=pins
                )
                retry_result.tls_valid = False
                retry_result.error_type = ProbeErrorType.TLS_ERROR.value
                retry_result.error_message = (
                    f"Certificate verification failed: {exc}. Host reachable without verification."
                )
                return retry_result
            except Exception as retry_exc:
                error_type, error_msg = _classify_exception(retry_exc)
                return UrlProbeResult(
                    url=target_url,
                    reachable=False,
                    tls_valid=False,
                    error_type=error_type,
                    error_message=(
                        f"Certificate verification failed: {exc}. Retry failed: {error_msg}"
                    ),
                )
            finally:
                retry_client.close()

        # Classify normal failures
        error_type, error_msg = _classify_exception(exc)
        return UrlProbeResult(
            url=target_url,
            reachable=False,
            tls_valid=False if (is_https and is_general_tls_error(exc)) else None,
            error_type=error_type,
            error_message=error_msg,
        )


def _classify_exception(exc: BaseException) -> tuple[str, str]:
    """Map an exception to standard ProbeErrorType and formatted message."""
    if isinstance(exc, DeadlineExceeded) or isinstance(exc, httpx.TimeoutException):
        return ProbeErrorType.TIMEOUT.value, str(exc)
    if is_general_tls_error(exc):
        return ProbeErrorType.TLS_ERROR.value, str(exc)
    if isinstance(exc, httpx.ConnectError):
        return ProbeErrorType.CONNECT_ERROR.value, str(exc)
    return ProbeErrorType.OTHER.value, str(exc)


def probe_host(
    hostname: str,
    base_domain: str,
    resolver: dns.resolver.Resolver | None = None,
    client: httpx.Client | None = None,
) -> HostProbeResult:
    """Probe a single host across HTTPS and HTTP endpoints on default ports.

    Includes domain re-validation and SSRF pre-check before making network calls.

    Args:
        hostname: Subdomain to probe.
        base_domain: Authorized root domain.
        resolver: Optional DNS resolver for SSRF checking.
        client: Optional httpx.Client instance for testing.

    Returns:
        HostProbeResult.
    """
    # 1. Re-validate domain and check scope
    validated_host, scope_error = validate_host_and_scope(hostname, base_domain)
    if not validated_host or scope_error:
        return HostProbeResult(
            subdomain=hostname,
            status=HostProbeStatus.SKIPPED_UNTRUSTED.value,
            skip_reason=scope_error,
        )

    # 2. SSRF Protection: resolve once, require public IPs, pin the address used
    pins: dict[str, str] = {}
    ip, reason = pin_host(validated_host, pins, resolver=resolver)
    if ip is None:
        return HostProbeResult(
            subdomain=validated_host,
            status=skip_status_for(reason),
            skip_reason=reason,
        )

    # 3. Create independent httpx.Client for this host (thread-safe)
    owns_client = client is None
    active_client = (
        client
        if client is not None
        else httpx.Client(
            verify=True,
            timeout=httpx.Timeout(TOTAL_URL_TIMEOUT, connect=CONNECT_TIMEOUT),
            headers=REQUEST_HEADERS,
        )
    )

    try:
        # Probe HTTPS first, then HTTP
        https_url = f"https://{validated_host}/"
        http_url = f"http://{validated_host}/"

        https_res = probe_url(
            https_url, base_domain, active_client, resolver=resolver, pins=pins
        )
        http_res = probe_url(http_url, base_domain, active_client, resolver=resolver, pins=pins)

        is_live = bool(https_res.reachable or http_res.reachable)

        preferred_url: str | None = None
        if https_res.reachable:
            preferred_url = https_res.final_url or https_res.url
        elif http_res.reachable:
            preferred_url = http_res.final_url or http_res.url

        return HostProbeResult(
            subdomain=validated_host,
            status=HostProbeStatus.PROBED.value,
            https=https_res,
            http=http_res,
            live=is_live,
            preferred_url=preferred_url,
        )
    finally:
        if owns_client:
            active_client.close()


def probe_hosts_concurrently(
    hosts: list[str],
    base_domain: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    resolver: dns.resolver.Resolver | None = None,
    client_factory: Any | None = None,
) -> list[HostProbeResult]:
    """Probe a list of hosts concurrently using a ThreadPoolExecutor.

    Args:
        hosts: List of hostnames to probe.
        base_domain: Authorized root domain.
        max_workers: Thread worker pool limit (default: 10).
        resolver: Optional resolver for tests.
        client_factory: Optional factory callable for tests.

    Returns:
        List of HostProbeResult sorted alphabetically by subdomain.
    """
    if not hosts:
        return []

    results: list[HostProbeResult] = []

    def _worker(h: str) -> HostProbeResult:
        c = client_factory() if client_factory is not None else None
        return probe_host(h, base_domain, resolver=resolver, client=c)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_worker, host): host for host in hosts}
        for future in futures:
            host = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                logger.error("Error probing host '%s': %s", host, exc)
                results.append(
                    HostProbeResult(
                        subdomain=host,
                        status=HostProbeStatus.PROBED.value,
                        skip_reason=f"Worker exception: {exc}",
                    )
                )

    results.sort(key=lambda r: r.subdomain)
    return results
