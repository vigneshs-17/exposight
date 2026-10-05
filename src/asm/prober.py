"""Active HTTP/HTTPS host prober module for ASM SaaS."""

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
    UNRESOLVED_REASON_PREFIX,
    check_host_for_ssrf,
    is_redirect_target_safe,
    is_safe_public_ip,
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
) -> UrlProbeResult:
    """Perform HTTP probe with manual redirect following and deadline enforcement.

    Follows up to 5 in-scope redirects manually. Records status code and reachability
    for all HTTP responses (including out-of-scope redirects and too many redirects).

    Args:
        target_url: URL to probe.
        base_domain: Root domain for scope checking.
        client: Pre-configured httpx.Client instance.
        deadline: Monotonic deadline timestamp.

    Returns:
        UrlProbeResult detailing outcome.
    """
    current_url = target_url
    redirect_chain: list[RedirectHop] = []
    follow_count = 0
    original_host = urllib.parse.urlsplit(target_url).hostname

    while True:
        if time.perf_counter() > deadline:
            raise DeadlineExceeded("10s total deadline exceeded before request dispatch")

        start_time = time.perf_counter()

        with client.stream("GET", current_url, follow_redirects=False) as response:
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
                hop_safe, hop_reason = is_redirect_target_safe(
                    next_url, original_host, resolver=resolver
                )
                if not hop_safe:
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

    Returns:
        UrlProbeResult.
    """
    deadline = time.perf_counter() + TOTAL_URL_TIMEOUT
    is_https = target_url.lower().startswith("https://")

    try:
        result = _execute_single_url_probe(
            target_url, base_domain, client, deadline, resolver=resolver
        )
        if is_https:
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
            # Create a separate client with verify=False solely for this retry attempt
            retry_client = httpx.Client(
                verify=False,
                timeout=httpx.Timeout(TOTAL_URL_TIMEOUT, connect=CONNECT_TIMEOUT),
                headers=REQUEST_HEADERS,
            )
            try:
                retry_result = _execute_single_url_probe(
                    target_url, base_domain, retry_client, deadline, resolver=resolver
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

    # 2. SSRF Protection: Pre-probe private IP check
    safe_ip, reason = check_host_for_ssrf(validated_host, resolver=resolver)
    if not safe_ip:
        unresolved = (reason or "").startswith(UNRESOLVED_REASON_PREFIX)
        return HostProbeResult(
            subdomain=validated_host,
            status=(
                HostProbeStatus.SKIPPED_UNRESOLVED.value
                if unresolved
                else HostProbeStatus.SKIPPED_PRIVATE_IP.value
            ),
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

        https_res = probe_url(https_url, base_domain, active_client, resolver=resolver)
        http_res = probe_url(http_url, base_domain, active_client, resolver=resolver)

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
