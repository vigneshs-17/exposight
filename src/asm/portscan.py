"""Lightweight, asynchronous TCP port scanner and service identifier for Exposight."""

from __future__ import annotations

import asyncio
import logging
import time

import dns.resolver

from asm.models import (
    HostPortScanResult,
    HostProbeStatus,
    PortResult,
    PortStatus,
)
from asm.scan_common import (
    is_safe_public_ip,
    resolve_host_ips,
    validate_host_and_scope,
)

logger = logging.getLogger(__name__)

# Fixed set of 16 common TCP ports (no arbitrary ports allowed)
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
]

# Static service dictionary mapping port numbers to standard service names
PORT_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

# Ports that speak first-line plaintext protocols requiring a CRLF prompt to return a banner
# Note: Port 22 (SSH) speaks first automatically; sending bytes breaks the SSH handshake!
FIRST_LINE_PROMPT_PORTS = {21, 25, 110, 143}

CONNECT_TIMEOUT_SECONDS = 3.0
BANNER_TIMEOUT_SECONDS = 2.0
MAX_BANNER_BYTES = 256
MAX_CONCURRENT_HOSTS = 5
MAX_CONCURRENT_PORTS_PER_HOST = 10
INTER_PORT_DELAY_SECONDS = 0.02


def compute_risk_flags(port: int) -> list[str]:
    """Evaluate informational security risk flags for an open port.

    Rules:
    - Database exposures: 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis).
    - Remote administration: 3389 (RDP), 23 (Telnet).
    - File sharing / Windows exposure: 445 (SMB).
    - Plaintext protocols: 21 (FTP), 23 (Telnet), 25 (SMTP), 110 (POP3), 143 (IMAP).
      Note: Ports 80, 8080, 443, 8443, and 22 are intentionally NOT flagged as plaintext.

    Args:
        port: TCP port number.

    Returns:
        List of uppercase risk flag strings.
    """
    flags: list[str] = []

    if port in (3306, 5432, 6379):
        flags.append("DATABASE_EXPOSURE")
    if port == 3389:
        flags.append("RDP_EXPOSURE")
    if port == 445:
        flags.append("SMB_EXPOSURE")
    if port == 23:
        flags.append("TELNET_INSECURE_REMOTE_ACCESS")

    # Plaintext protocols (legacy unencrypted services)
    if port in (21, 23, 25, 110, 143):
        flags.append("PLAINTEXT_PROTOCOL")

    return flags


def sanitize_banner(raw_bytes: bytes) -> str | None:
    """Sanitize raw banner bytes into a single-line, printable string.

    Strips binary control characters, collapses whitespace, and limits length to 256 chars.

    Args:
        raw_bytes: Raw bytes received from the socket.

    Returns:
        Clean printable banner string, or None if empty or unparseable.
    """
    if not raw_bytes:
        return None

    try:
        decoded = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    # Filter for printable characters and standard spaces
    printable_chars = [c for c in decoded if c.isprintable() or c in (" ", "\t")]
    cleaned = " ".join("".join(printable_chars).split()).strip()

    if not cleaned:
        return None

    if len(cleaned) > MAX_BANNER_BYTES:
        cleaned = cleaned[:MAX_BANNER_BYTES]

    return cleaned


async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
) -> str | None:
    """Safely attempt to read a service identification banner from an open port.

    Rules:
    - Port 22 (SSH): Send nothing, only listen (SSH servers speak first).
    - Ports 21, 25, 110, 143: Send a single CRLF to trigger server greeting.
    - All other ports: Send nothing, listen passively for up to 2 seconds.
    - Never send protocol-specific exploits or fuzzing payloads.

    Args:
        reader: StreamReader for the connected socket.
        writer: StreamWriter for the connected socket.
        port: Target TCP port number.

    Returns:
        Sanitized banner string, or None on error/timeout.
    """
    try:
        # Prompt only protocols that wait for a client ping before speaking
        if port in FIRST_LINE_PROMPT_PORTS:
            writer.write(b"\r\n")
            await writer.drain()

        # Read at most 256 bytes within the banner timeout
        raw_data = await asyncio.wait_for(
            reader.read(MAX_BANNER_BYTES),
            timeout=BANNER_TIMEOUT_SECONDS,
        )
        return sanitize_banner(raw_data)
    except Exception:
        return None


async def scan_single_port(
    host: str,
    port: int,
    port_semaphore: asyncio.Semaphore,
) -> PortResult:
    """Perform a plain TCP connect scan against a single port.

    Classifies port as:
    - OPEN: Connection established successfully.
    - CLOSED: Connection refused by target OS (RST received).
    - FILTERED: Connection timed out or packet dropped (likely firewall).

    Args:
        host: Hostname or IP to scan.
        port: Fixed TCP port number.
        port_semaphore: Concurrency limiter per host.

    Returns:
        PortResult detailing state, guessed service, banner, and risk flags.
    """
    # Strict validation: Never scan a port outside the fixed default list
    if port not in DEFAULT_PORTS:
        raise ValueError(f"Port {port} is not permitted in fixed port list")

    service_name = PORT_SERVICES.get(port, "unknown")
    service_guess = f"{service_name} (guess by port)"
    risk_flags = compute_risk_flags(port)

    async with port_semaphore:
        # Polite pacing between connections to the same host
        if INTER_PORT_DELAY_SECONDS > 0:
            await asyncio.sleep(INTER_PORT_DELAY_SECONDS)

        start_time = time.perf_counter()
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )

            # Rule 1: A port is OPEN only when asyncio.open_connection fully succeeds
            # AND returns a usable connection (reader/writer, no exception).
            # Anything else is not OPEN.
            if reader is None or writer is None:
                return PortResult(
                    port=port,
                    state=PortStatus.FILTERED.value,
                    service_guess=service_guess,
                )

            is_closing_func = getattr(writer, "is_closing", None)
            if callable(is_closing_func) and is_closing_func() is True:
                return PortResult(
                    port=port,
                    state=PortStatus.FILTERED.value,
                    service_guess=service_guess,
                )

            at_eof_func = getattr(reader, "at_eof", None)
            if callable(at_eof_func) and at_eof_func() is True:
                return PortResult(
                    port=port,
                    state=PortStatus.FILTERED.value,
                    service_guess=service_guess,
                )

            sock = writer.get_extra_info("socket")
            if sock is not None and getattr(sock, "fileno", lambda: 0)() == -1:
                return PortResult(
                    port=port,
                    state=PortStatus.FILTERED.value,
                    service_guess=service_guess,
                )

            response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Connected! Grab optional minimal banner
            banner = await grab_banner(reader, writer, port)

            return PortResult(
                port=port,
                state=PortStatus.OPEN.value,
                service_guess=service_guess,
                banner=banner,
                risk_flags=risk_flags,
                response_time_ms=response_time_ms,
            )

        except ConnectionRefusedError:
            # Explicit RST packet received from host: host is UP, port is CLOSED
            response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return PortResult(
                port=port,
                state=PortStatus.CLOSED.value,
                service_guess=service_guess,
                response_time_ms=response_time_ms,
            )

        except TimeoutError:
            # Packet dropped without response: likely blocked by a firewall
            return PortResult(
                port=port,
                state=PortStatus.FILTERED.value,
                service_guess=service_guess,
            )

        except OSError as exc:
            # Distinguish connection refused on Windows/Unix from other network errors
            err_str = str(exc).lower()
            if "refused" in err_str or getattr(exc, "winerror", None) == 10061:
                return PortResult(
                    port=port,
                    state=PortStatus.CLOSED.value,
                    service_guess=service_guess,
                )
            # Other network/unreachable errors mapped to FILTERED
            return PortResult(
                port=port,
                state=PortStatus.FILTERED.value,
                service_guess=service_guess,
            )

        except Exception as exc:
            logger.debug("Unexpected error scanning port %d on %s: %s", port, host, exc)
            return PortResult(
                port=port,
                state=PortStatus.FILTERED.value,
                service_guess=service_guess,
            )

        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass


async def scan_host_ports(
    hostname: str,
    base_domain: str,
    host_semaphore: asyncio.Semaphore,
    resolver: dns.resolver.Resolver | None = None,
) -> HostPortScanResult:
    """Validate, inspect SSRF safety, and scan fixed ports for a single host.

    Rules:
    - Re-validates domain syntax and scope (fails -> SKIPPED_UNTRUSTED).
    - Resolves DNS: if host fails resolution (NXDOMAIN or empty), skips with
      SKIPPED_UNRESOLVED and allows the scan to continue.
    - SSRF pre-check: if any resolved IP is non-public, skips with SKIPPED_PRIVATE_IP.
    - Limits concurrency to max 10 concurrent ports per host.

    Args:
        hostname: Subdomain to scan.
        base_domain: Authorized root domain.
        host_semaphore: Concurrency limiter across hosts.
        resolver: Optional Resolver instance for tests.

    Returns:
        HostPortScanResult.
    """
    async with host_semaphore:
        # 1. Scope & syntax check
        validated_host, scope_error = validate_host_and_scope(hostname, base_domain)
        if not validated_host or scope_error:
            return HostPortScanResult(
                subdomain=hostname,
                status=HostProbeStatus.SKIPPED_UNTRUSTED.value,
                skip_reason=scope_error,
            )

        # 2. DNS Resolution & SSRF Guard
        # dnspython resolution is blocking; run it in a worker thread so one slow
        # lookup does not stall the event loop (and every other host's port scan).
        resolved_ips = await asyncio.to_thread(
            resolve_host_ips, validated_host, resolver=resolver
        )
        if not resolved_ips:
            # Per requirement 4: If a host fails DNS at scan time, record as SKIPPED_UNRESOLVED
            return HostPortScanResult(
                subdomain=validated_host,
                status=HostProbeStatus.SKIPPED_UNRESOLVED.value,
                skip_reason=f"Host '{validated_host}' failed DNS resolution at scan time",
            )

        for ip in resolved_ips:
            if not is_safe_public_ip(ip):
                return HostPortScanResult(
                    subdomain=validated_host,
                    status=HostProbeStatus.SKIPPED_PRIVATE_IP.value,
                    skip_reason=f"Host resolved to non-public/private IP: {ip}",
                )

        # 3. Concurrently scan the fixed 16 ports with max 10 parallel ports per host
        port_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PORTS_PER_HOST)
        tasks = [
            scan_single_port(validated_host, port, port_semaphore)
            for port in DEFAULT_PORTS
        ]
        port_results = await asyncio.gather(*tasks)

        open_ports: list[PortResult] = []
        closed_ports: list[int] = []
        filtered_ports: list[int] = []
        all_risk_flags: set[str] = set()

        for res in port_results:
            if res.state == PortStatus.OPEN.value:
                open_ports.append(res)
                all_risk_flags.update(res.risk_flags)
            elif res.state == PortStatus.CLOSED.value:
                closed_ports.append(res.port)
            else:
                filtered_ports.append(res.port)

        # Sort ports numerically
        open_ports.sort(key=lambda p: p.port)
        closed_ports.sort()
        filtered_ports.sort()

        return HostPortScanResult(
            subdomain=validated_host,
            status=HostProbeStatus.PROBED.value,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ports=filtered_ports,
            risk_flags=sorted(all_risk_flags),
        )


async def _run_port_scan_async(
    hosts: list[str],
    base_domain: str,
    max_hosts: int = MAX_CONCURRENT_HOSTS,
    resolver: dns.resolver.Resolver | None = None,
) -> list[HostPortScanResult]:
    """Execute asynchronous port scanning across all hosts with concurrency bounding."""
    host_semaphore = asyncio.Semaphore(max_hosts)
    tasks = [
        scan_host_ports(host, base_domain, host_semaphore, resolver=resolver)
        for host in hosts
    ]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.subdomain)


def run_port_scan(
    hosts: list[str],
    base_domain: str,
    max_hosts: int = MAX_CONCURRENT_HOSTS,
    resolver: dns.resolver.Resolver | None = None,
) -> list[HostPortScanResult]:
    """Synchronous entry point to run asynchronous port scanning.

    Args:
        hosts: List of resolved hostnames to scan.
        base_domain: Authorized root domain.
        max_hosts: Maximum concurrent hosts scanned in parallel (default: 5).
        resolver: Optional DNS resolver for tests.

    Returns:
        List of HostPortScanResult sorted alphabetically by subdomain.
    """
    if not hosts:
        return []

    return asyncio.run(
        _run_port_scan_async(
            hosts,
            base_domain,
            max_hosts=max_hosts,
            resolver=resolver,
        )
    )
