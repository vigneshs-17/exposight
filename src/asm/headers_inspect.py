"""HTTP security headers inspection and single-connection TLS coordinator for ASM SaaS.

Evaluates security headers (HSTS, CSP, X-Frame-Options, etc.), parses HSTS max-age,
and detects information disclosure headers (Server, X-Powered-By, X-AspNet-Version).
Coordinates single-connection TLS inspection with fallback to raw sockets.
"""

from __future__ import annotations

import datetime
import logging
import re
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from asm.models import CertInfo, HeaderInfo, HostInspectResult, HostProbeStatus, InspectReport
from asm.scan_common import check_host_for_ssrf, validate_host_and_scope
from asm.tls_inspect import connect_and_inspect_cert_socket, parse_cert_dict

logger = logging.getLogger(__name__)

# Standard security headers to evaluate
MONITORED_SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Information disclosure headers that leak server software versions
INFO_DISCLOSURE_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
]

# HTTP client parameters matching Step 2 specifications
TIMEOUT_CONFIG = httpx.Timeout(10.0, connect=5.0)
TOTAL_DEADLINE_SECONDS = 15.0
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 65536
USER_AGENT = "Exposight/0.1 (+https://github.com/vigneshs-17/asm-saas)"
HSTS_MIN_RECOMMENDED_MAX_AGE = 15552000  # 180 days in seconds


def parse_hsts_header(hsts_value: str | None) -> tuple[int | None, bool]:
    """Parse Strict-Transport-Security header value for max-age and weakness.

    Args:
        hsts_value: Raw header value (e.g. 'max-age=31536000; includeSubDomains').

    Returns:
        Tuple of (max_age_seconds, hsts_weak).
    """
    if not hsts_value:
        return None, False

    match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
    if not match:
        # Header present but lacks valid max-age directive
        return None, True

    max_age = int(match.group(1))
    hsts_weak = max_age < HSTS_MIN_RECOMMENDED_MAX_AGE
    return max_age, hsts_weak


def extract_header_info(
    headers: httpx.Headers | dict[str, str], error: str | None = None
) -> HeaderInfo:
    """Extract monitored security headers, evaluate weaknesses, and identify disclosures.

    Args:
        headers: HTTP response headers.
        error: Optional error string if request encountered issues.

    Returns:
        Populated HeaderInfo dataclass.
    """
    present_headers: dict[str, str] = {}
    missing_headers: list[str] = []

    # 1. Monitored security headers
    for h in MONITORED_SECURITY_HEADERS:
        val = headers.get(h)
        if val is not None:
            present_headers[h] = val
        else:
            missing_headers.append(h)

    # 2. HSTS evaluation
    hsts_val = present_headers.get("Strict-Transport-Security")
    hsts_max_age, hsts_weak = parse_hsts_header(hsts_val)

    # 3. Information disclosure
    server_val = headers.get("Server")
    x_powered_by_val = headers.get("X-Powered-By")
    x_aspnet_val = headers.get("X-AspNet-Version")

    return HeaderInfo(
        present_headers=present_headers,
        missing_headers=missing_headers,
        hsts_max_age=hsts_max_age,
        hsts_weak=hsts_weak,
        server=server_val,
        x_powered_by=x_powered_by_val,
        x_aspnet_version=x_aspnet_val,
        server_disclosed=bool(server_val),
        x_powered_by_disclosed=bool(x_powered_by_val),
        x_aspnet_version_disclosed=bool(x_aspnet_val),
        error=error,
    )


def is_redirect_in_scope(target_url: str, base_domain: str) -> bool:
    """Verify that a redirect URL remains within the allowed base domain and safe ports."""
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
        if not (hostname == base_domain or hostname.endswith("." + base_domain)):
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return port in (80, 443)
    except Exception:
        return False


def inspect_single_host(
    hostname: str,
    base_domain: str,
    timeout_config: httpx.Timeout = TIMEOUT_CONFIG,
    total_deadline: float = TOTAL_DEADLINE_SECONDS,
) -> HostInspectResult:
    """Inspect TLS certificate and HTTP security headers for a single HTTPS host.

    Prefers a single connection per host:
    - Makes a verified GET request to https://<hostname>/ with httpx.
    - Extracts headers directly from the HTTP response.
    - Extracts the active SSL peer certificate from the underlying network_stream.
    - If reading from the network_stream fails (e.g. stream closed, None, empty dict)
      or if verification fails, falls back to a direct ssl+socket connection to 443.

    Args:
        hostname: Subdomain to inspect.
        base_domain: Authorized root domain for redirect scope checks.
        timeout_config: Client timeout configuration.
        total_deadline: Total wall-clock deadline in seconds.

    Returns:
        HostInspectResult.
    """
    start_time = time.perf_counter()
    headers_info: HeaderInfo | None = None
    cert_info: CertInfo | None = None
    initial_url = f"https://{hostname}/"

    # Step A: Attempt primary HTTPS GET with TLS verification enabled
    headers = {"User-Agent": USER_AGENT}
    response: httpx.Response | None = None
    last_verify_error: str | None = None

    try:
        with httpx.Client(
            timeout=timeout_config,
            follow_redirects=False,
            verify=True,
            headers=headers,
        ) as client:
            current_url = initial_url
            redirect_hops = 0

            while redirect_hops <= MAX_REDIRECTS:
                if (time.perf_counter() - start_time) > total_deadline:
                    raise TimeoutError(f"Inspection deadline of {total_deadline}s exceeded")

                resp = client.get(current_url)

                # Read body up to 64KB
                _ = resp.read()[:MAX_RESPONSE_BYTES]
                response = resp

                # Handle manual in-scope redirects
                has_loc = "location" in resp.headers
                if resp.is_redirect and has_loc and redirect_hops < MAX_REDIRECTS:
                    loc = resp.headers["location"]
                    next_url = str(resp.url.join(loc))
                    if is_redirect_in_scope(next_url, base_domain):
                        current_url = next_url
                        redirect_hops += 1
                        continue
                break

    except httpx.ConnectError as conn_err:
        # Walk exception chain to detect underlying TLS verification failures
        curr: BaseException | None = conn_err
        ssl_cause: ssl.SSLError | None = None
        visited: set[int] = set()
        while curr is not None and id(curr) not in visited:
            if isinstance(curr, ssl.SSLError):
                ssl_cause = curr
                break
            visited.add(id(curr))
            curr = curr.__cause__ or curr.__context__

        if ssl_cause is not None:
            last_verify_error = str(ssl_cause)
            logger.debug("TLS verification failed on %s: %s", hostname, ssl_cause)
        else:
            logger.debug("Connect failed on %s: %s", hostname, conn_err)

    except (httpx.TimeoutException, TimeoutError) as t_err:
        logger.debug("Timeout connecting to %s: %s", hostname, t_err)

    except Exception as exc:
        logger.debug("Unexpected error connecting to %s: %s", hostname, exc)

    # Step B: If verified GET succeeded, extract headers and attempt to extract cert from stream
    if response is not None:
        headers_info = extract_header_info(response.headers)

        # Attempt to read cert from the underlying response network_stream
        try:
            stream = response.extensions.get("network_stream")
            ssl_object = stream.get_extra_info("ssl_object") if stream else None
            if ssl_object is not None:
                cert_dict = ssl_object.getpeercert()
                tls_version = ssl_object.version()
                if cert_dict:
                    cert_info = parse_cert_dict(
                        cert_dict=cert_dict,
                        hostname=hostname,
                        tls_version=tls_version,
                        is_trusted=True,
                        verify_error=None,
                        source="from_response",
                    )
        except Exception as stream_err:
            logger.debug("Could not read cert from network_stream on %s: %s", hostname, stream_err)
            cert_info = None

    # Step C: Fallback to direct ssl+socket connection if cert could not be read from response
    if cert_info is None:
        # Either the verified GET failed with TLS error, stream read returned None/empty,
        # or GET timed out
        remaining_time = max(1.0, total_deadline - (time.perf_counter() - start_time))
        cert_info = connect_and_inspect_cert_socket(
            hostname=hostname,
            port=443,
            timeout=min(5.0, remaining_time),
        )

    # Step D: If verified request failed due to TLS error, try unverified GET to still get headers
    if headers_info is None and last_verify_error is not None:
        try:
            remaining_time = max(1.0, total_deadline - (time.perf_counter() - start_time))
            unverified_timeout = httpx.Timeout(
                min(5.0, remaining_time), connect=min(3.0, remaining_time)
            )
            with httpx.Client(
                timeout=unverified_timeout,
                follow_redirects=False,
                verify=False,
                headers=headers,
            ) as unverified_client:
                unverified_resp = unverified_client.get(initial_url)
                headers_info = extract_header_info(unverified_resp.headers)
        except Exception as unverified_hdr_err:
            headers_info = HeaderInfo(error=f"Could not fetch headers: {unverified_hdr_err}")

    # Step E: Handle unreachable host
    if cert_info is None and headers_info is None:
        return HostInspectResult(
            subdomain=hostname,
            status=HostProbeStatus.PROBED.value,
            skip_reason="Port 443 / HTTPS unreachable or connection timed out",
            cert=None,
            headers=None,
        )

    return HostInspectResult(
        subdomain=hostname,
        status=HostProbeStatus.PROBED.value,
        skip_reason=None,
        cert=cert_info,
        headers=headers_info,
    )


def run_inspection(
    probe_results: list[dict[str, Any]],
    base_domain: str,
    source_report_name: str,
) -> InspectReport:
    """Run TLS and HTTP security header inspections on live HTTPS hosts from a probe report.

    Args:
        probe_results: List of host result dictionaries from the input probe report.
        base_domain: Target root domain for scope validation.
        source_report_name: Filename of the source probe report.

    Returns:
        InspectReport containing host findings and summary counts.
    """
    start_time_utc = datetime.datetime.now(datetime.UTC).isoformat()
    results: list[HostInspectResult] = []

    hosts_inspected = 0
    certs_valid = 0
    certs_expired = 0
    certs_expiring_soon = 0
    hosts_missing_hsts = 0
    skipped_untrusted = 0
    skipped_private_ip = 0
    skipped_not_https = 0

    for entry in probe_results:
        subdomain = entry.get("subdomain", "")
        status = entry.get("status", "")
        https_info = entry.get("https") or {}
        https_reachable = https_info.get("reachable") is True

        # Rule 7: Only inspect hosts that were reachable over HTTPS in the probe report
        if status != HostProbeStatus.PROBED.value or not https_reachable:
            skipped_not_https += 1
            results.append(
                HostInspectResult(
                    subdomain=subdomain,
                    status=HostProbeStatus.SKIPPED_NOT_HTTPS.value,
                    skip_reason="Host was not reachable over HTTPS in probe report",
                )
            )
            continue

        # 1. Scope & syntax check
        validated_host, scope_error = validate_host_and_scope(subdomain, base_domain)
        if not validated_host or scope_error:
            skipped_untrusted += 1
            results.append(
                HostInspectResult(
                    subdomain=subdomain,
                    status=HostProbeStatus.SKIPPED_UNTRUSTED.value,
                    skip_reason=scope_error or "Hostname failed scope check",
                )
            )
            continue

        # 2. SSRF check
        is_safe, ssrf_reason = check_host_for_ssrf(validated_host)
        if not is_safe:
            skipped_private_ip += 1
            results.append(
                HostInspectResult(
                    subdomain=validated_host,
                    status=HostProbeStatus.SKIPPED_PRIVATE_IP.value,
                    skip_reason=ssrf_reason,
                )
            )
            continue

        # 3. Perform inspection
        res = inspect_single_host(validated_host, base_domain)
        results.append(res)
        hosts_inspected += 1

        # Summary statistics calculation
        if res.cert is not None:
            if res.cert.is_trusted and not res.cert.expired and not res.cert.hostname_mismatch:
                certs_valid += 1
            if res.cert.expired:
                certs_expired += 1
            if res.cert.expiring_soon:
                certs_expiring_soon += 1

        if res.headers is None or "Strict-Transport-Security" in res.headers.missing_headers:
            hosts_missing_hsts += 1

    finish_time_utc = datetime.datetime.now(datetime.UTC).isoformat()

    counts = {
        "hosts_inspected": hosts_inspected,
        "certs_valid": certs_valid,
        "certs_expired": certs_expired,
        "certs_expiring_soon": certs_expiring_soon,
        "hosts_missing_hsts": hosts_missing_hsts,
        "skipped_untrusted": skipped_untrusted,
        "skipped_private_ip": skipped_private_ip,
        "skipped_not_https": skipped_not_https,
    }

    return InspectReport(
        domain=base_domain,
        source_report=source_report_name,
        inspect_started_utc=start_time_utc,
        inspect_finished_utc=finish_time_utc,
        counts=counts,
        results=results,
    )
