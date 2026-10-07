"""Shared security, validation, and report loading utilities for ASM scans."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import dns.resolver

from asm.models import HostProbeStatus
from asm.validators import DomainValidationError, validate_domain

logger = logging.getLogger(__name__)

# Reason prefix returned by check_host_for_ssrf when a host has no A/AAAA answer.
# Callers use it to report SKIPPED_UNRESOLVED instead of SKIPPED_PRIVATE_IP.
UNRESOLVED_REASON_PREFIX = "Host did not resolve"

# Reason prefix for a host whose validated addresses are all IPv6 while IPv6 scanning
# is off (D12). Callers report SKIPPED_IPV6_ONLY: the host is not down, we did not try.
IPV6_ONLY_REASON_PREFIX = "IPv6-only host"

# IPv6 ranges that embed an IPv4 address or are deprecated-internal.
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
_SIX_TO_FOUR_PREFIX = ipaddress.IPv6Network("2002::/16")
_SITE_LOCAL_PREFIX = ipaddress.IPv6Network("fec0::/10")


def sanitize_error_text(error: str | None, max_length: int = 300) -> str | None:
    """Sanitize error text by stripping control characters and truncating to max_length."""
    if error is None:
        return None
    cleaned = "".join(
        ch
        for ch in error
        if not (ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch).startswith("C"))
    )
    return cleaned[:max_length]


class ReportValidationError(Exception):
    """Raised when an input discovery report is missing, malformed, or invalid."""


def load_and_validate_report(
    report_path_str: str,
) -> tuple[dict[str, Any], str, list[str], int]:
    """Load and validate a Step 1 discovery report JSON file.

    Treats the input report as untrusted data:
    - Verifies file existence.
    - Validates JSON format.
    - Requires a non-empty 'domain' string.
    - Requires a 'results' list.
    - Extracts hostnames where status == 'RESOLVED' or resolved is True.
    - Counts skipped unresolved hosts.

    Args:
        report_path_str: Path to the discovery report JSON file.

    Returns:
        Tuple of (raw_report_dict, target_domain, resolved_hosts, skipped_unresolved_count).

    Raises:
        ReportValidationError: If the file cannot be found, parsed, or lacks required fields.
    """
    report_path = Path(report_path_str)
    if not report_path.is_file():
        raise ReportValidationError(f"Discovery report file not found: {report_path_str}")

    try:
        with report_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise ReportValidationError(f"Failed to parse discovery report JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ReportValidationError("Discovery report JSON root must be an object")

    domain = data.get("domain")
    if not domain or not isinstance(domain, str):
        raise ReportValidationError("Discovery report is missing a valid 'domain' field")

    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise ReportValidationError("Discovery report 'results' field must be a list")

    resolved_hosts: list[str] = []
    skipped_unresolved_count = 0

    for item in raw_results:
        if isinstance(item, dict):
            subdomain = item.get("subdomain")
            if not subdomain or not isinstance(subdomain, str):
                continue
            is_resolved = item.get("resolved") is True or item.get("status") == "RESOLVED"
            if is_resolved:
                resolved_hosts.append(subdomain)
            else:
                skipped_unresolved_count += 1

    return data, domain, resolved_hosts, skipped_unresolved_count


def load_and_validate_generic_report(
    report_path_str: str,
    report_type: str = "report",
    expected_domain: str | None = None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Load and validate an untrusted scan report JSON file.

    Treats the input report as untrusted data:
    - Verifies file existence.
    - Validates JSON format and root dictionary structure.
    - Requires a non-empty 'domain' string.
    - Asserts domain matches expected_domain if specified.
    - Requires a 'results' list of dictionaries.

    Args:
        report_path_str: Path to the JSON report file.
        report_type: Descriptive name for errors (e.g. 'probe', 'inspect').
        expected_domain: Optional expected domain to check for agreement.

    Returns:
        Tuple of (raw_report_dict, target_domain, results_list).

    Raises:
        ReportValidationError: On missing, malformed, or mismatched domain report.
    """
    report_path = Path(report_path_str)
    type_name = report_type.capitalize()
    if not report_path.is_file():
        raise ReportValidationError(f"{type_name} report file not found: {report_path_str}")

    try:
        with report_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise ReportValidationError(f"Failed to parse {report_type} report JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ReportValidationError(f"{type_name} report JSON root must be an object")

    domain = data.get("domain")
    if not domain or not isinstance(domain, str):
        raise ReportValidationError(f"{type_name} report is missing a valid 'domain' field")

    if expected_domain and domain.strip().lower() != expected_domain.strip().lower():
        msg = f"{type_name} report domain '{domain}' does not match expected '{expected_domain}'"
        raise ReportValidationError(msg)

    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise ReportValidationError(f"{type_name} report 'results' field must be a list")

    dict_results = [r for r in raw_results if isinstance(r, dict)]
    return data, domain, dict_results


def is_safe_public_ip(ip_str: str) -> bool:
    """Check if an IP address is a safe, globally routable public address.

    First unwraps IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1),
    then verifies that ip.is_global is True and ip.is_multicast is False.
    This safely filters out:
    - Private networks (RFC 1918)
    - Loopback addresses (127.0.0.0/8, ::1)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Reserved ranges
    - CGNAT addresses (100.64.0.0/10)
    - Unspecified addresses (0.0.0.0, ::)
    - Multicast groups

    Args:
        ip_str: The IP address string to check.

    Returns:
        True if the IP is globally routable and public, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            # IPv4-mapped (::ffff:127.0.0.1 -> 127.0.0.1)
            ip = ip.ipv4_mapped
        elif ip in _NAT64_PREFIX:
            # NAT64 (64:ff9b::7f00:1 -> 127.0.0.1): judge the embedded IPv4 address
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip in _SIX_TO_FOUR_PREFIX:
            # 6to4 (2002:7f00:1::/48 -> 127.0.0.1): IPv4 sits in bits 16-48
            ip = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
        elif (int(ip) >> 32) == 0 and int(ip) > 1:
            # Deprecated IPv4-compatible form (::7f00:1 -> 127.0.0.1); :: and ::1 stay IPv6
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip in _SITE_LOCAL_PREFIX:
            # Deprecated site-local fec0::/10 is internal but not flagged by is_global
            return False

    return bool(ip.is_global and not ip.is_multicast)


def resolve_host_ips(
    hostname: str,
    resolver: dns.resolver.Resolver | None = None,
) -> list[str]:
    """Resolve A and AAAA DNS records for a hostname.

    Args:
        hostname: The hostname to resolve.
        resolver: Optional configured Resolver instance.

    Returns:
        List of resolved IP address strings (may be empty if resolution fails).
    """
    active_resolver = resolver if resolver is not None else dns.resolver.Resolver()
    active_resolver.lifetime = 3.0
    active_resolver.timeout = 3.0

    resolved_ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answers = active_resolver.resolve(hostname, rdtype)
            for rdata in answers:
                resolved_ips.append(rdata.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as exc:
            logger.debug("DNS check error for %s (%s): %s", hostname, rdtype, exc)

    return resolved_ips


def resolve_public_ips(
    hostname: str,
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[list[str] | None, str | None]:
    """Resolve a host once and return its addresses only if EVERY one is public.

    Fails CLOSED: a host with no A/AAAA answer (NXDOMAIN, timeout, SERVFAIL) is not
    safe. Returns (ips, None) or (None, reason); an unresolved reason starts with
    UNRESOLVED_REASON_PREFIX.
    """
    resolved_ips = resolve_host_ips(hostname, resolver=resolver)

    if not resolved_ips:
        return None, f"{UNRESOLVED_REASON_PREFIX}: '{hostname}' has no A/AAAA answer"

    for ip in resolved_ips:
        if not is_safe_public_ip(ip):
            return None, f"Host '{hostname}' resolved to non-public/private IP: {ip}"

    return resolved_ips, None


def check_host_for_ssrf(
    hostname: str,
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[bool, str | None]:
    """Resolve a host and check whether any resolved IP is internal/private.

    Boolean form of resolve_public_ips. Scanners connect through pin_host instead,
    so the address that passed this check is the only one they ever contact.

    Returns:
        (True, None) if safe, or (False, reason) if unresolved or any IP is non-public.
    """
    ips, reason = resolve_public_ips(hostname, resolver=resolver)
    return ips is not None, reason


def ipv6_scanning_enabled() -> bool:
    """Return True only when SCAN_IPV6_ENABLED is explicitly turned on (D12: off)."""
    return os.getenv("SCAN_IPV6_ENABLED", "false").strip().lower() in ("true", "1", "yes")


def pick_ip(hostname: str, ips: list[str]) -> tuple[str | None, str | None]:
    """Choose the address to connect to: the first IPv4, else the first IPv6 (D11).

    With IPv6 scanning off, a host with only IPv6 addresses is not contacted and the
    reason starts with IPV6_ONLY_REASON_PREFIX, so it is reported as skipped rather
    than unreachable.
    """
    for ip in ips:
        if ipaddress.ip_address(ip).version == 4:
            return ip, None
    if ips and ipv6_scanning_enabled():
        return ips[0], None
    return None, (
        f"{IPV6_ONLY_REASON_PREFIX}: '{hostname}' has only IPv6 addresses "
        f"and IPv6 scanning is off: {', '.join(ips)}"
    )


def pin_host(
    hostname: str,
    pins: dict[str, str],
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[str | None, str | None]:
    """Return the one IP this scan may use for hostname, resolving it at most once.

    DNS-rebinding guard: the address that passed the public-IP check is stored in
    pins and every later connection to this host (retries, redirect hops back to it)
    uses it; the hostname is never handed to a library that would resolve it again.
    """
    host = hostname.lower().rstrip(".")
    if host in pins:
        return pins[host], None
    ips, reason = resolve_public_ips(host, resolver=resolver)
    if ips is None:
        return None, reason
    ip, reason = pick_ip(host, ips)
    if ip is None:
        return None, reason
    pins[host] = ip
    return ip, None


def pinned_request(url: str, ip: str) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Build an httpx request that connects to ip while speaking to the URL's host.

    Returns (wire_url, headers, extensions) for client.stream/request: the URL
    carries the IP, the Host header carries the hostname (and a non-default port),
    and for HTTPS httpcore's "sni_hostname" extension sets SNI and the name the
    certificate is verified against. "Connection: close" stops httpcore from reusing
    a connection opened with another host's SNI for a different host on the same IP.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    netloc = f"[{ip}]" if ":" in ip else ip
    host_header = host
    if parts.port is not None:
        netloc += f":{parts.port}"
        host_header += f":{parts.port}"
    wire_url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    extensions: dict[str, Any] = {"sni_hostname": host} if parts.scheme == "https" else {}
    return wire_url, {"Host": host_header, "Connection": "close"}, extensions


def skip_status_for(reason: str | None) -> str:
    """Map a pin_host/resolve_public_ips refusal reason to a HostProbeStatus value."""
    text = reason or ""
    if text.startswith(UNRESOLVED_REASON_PREFIX):
        return HostProbeStatus.SKIPPED_UNRESOLVED.value
    if text.startswith(IPV6_ONLY_REASON_PREFIX):
        return HostProbeStatus.SKIPPED_IPV6_ONLY.value
    return HostProbeStatus.SKIPPED_PRIVATE_IP.value


def validate_host_and_scope(
    hostname: str,
    base_domain: str,
) -> tuple[str | None, str | None]:
    """Validate a hostname's syntax and ensure it belongs to the target domain scope.

    Args:
        hostname: Subdomain string from untrusted report.
        base_domain: Root domain authorized for testing.

    Returns:
        Tuple of (validated_hostname, None) on success, or (None, failure_reason).
    """
    try:
        validated_host = validate_domain(hostname)
    except DomainValidationError as exc:
        return None, f"Failed domain validation: {exc}"

    norm_base = base_domain.lower().rstrip(".")
    if not (validated_host == norm_base or validated_host.endswith(f".{norm_base}")):
        return None, f"Host '{hostname}' is out of scope for root domain '{base_domain}'"

    return validated_host, None
