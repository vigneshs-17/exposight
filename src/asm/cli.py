"""Command-line interface (CLI) for Exposight."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from asm.discovery import (
    DiscoveryError,
    discover_subdomains,
    fetch_crtsh_data,
)
from asm.headers_inspect import run_inspection
from asm.models import (
    DiscoveryReport,
    HostPortScanResult,
    HostProbeResult,
    HostProbeStatus,
    PortScanReport,
    ProbeReport,
    SubdomainResult,
)
from asm.portscan import DEFAULT_PORTS, run_port_scan
from asm.prober import probe_hosts_concurrently
from asm.resolver import resolve_subdomains_concurrently
from asm.scan_common import ReportValidationError, load_and_validate_report
from asm.scoring import score_domain_reports
from asm.validators import DomainValidationError, validate_domain

logger = logging.getLogger("asm")


def setup_logging(verbose: bool = False) -> None:
    """Configure standard library logging format and log level."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not verbose:
        # Silence noisy third-party and standard library logs unless verbose (-v) is enabled
        for noisy_logger in ("httpx", "httpcore", "asyncio"):
            logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="asm",
        description="Exposight - Attack Surface Management CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: discover
    discover_parser = subparsers.add_parser(
        "discover",
        help="Passively discover subdomains via Certificate Transparency logs (crt.sh)",
    )
    discover_parser.add_argument(
        "domain",
        help="Target domain to scan (e.g. 'example.com' or 'https://example.com')",
    )
    discover_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON discovery report (default: output)",
    )
    discover_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: probe
    probe_parser = subparsers.add_parser(
        "probe",
        help="Actively probe resolved hosts for live HTTP/HTTPS services",
    )
    probe_parser.add_argument(
        "report_file",
        help="Path to Step 1 discovery report JSON file",
    )
    probe_parser.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Confirm authorization to perform active network requests against target domain",
    )
    probe_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON probe report (default: output)",
    )
    probe_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: portscan
    portscan_parser = subparsers.add_parser(
        "portscan",
        help="Actively scan common TCP ports on resolved hosts",
    )
    portscan_parser.add_argument(
        "report_file",
        help="Path to Step 1 discovery report JSON file",
    )
    portscan_parser.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Confirm authorization to perform active port scanning against target domain",
    )
    portscan_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON port scan report (default: output)",
    )
    portscan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: inspect
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect TLS certificates and HTTP security headers for live HTTPS hosts",
    )
    inspect_parser.add_argument(
        "report_file",
        help="Path to Step 2 probe report JSON file",
    )
    inspect_parser.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Confirm authorization to perform active inspection against target domain",
    )
    inspect_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON inspect report (default: output)",
    )
    inspect_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: score
    score_parser = subparsers.add_parser(
        "score",
        help="Compute risk scores and aggregate multi-stage reports for a domain",
    )
    score_parser.add_argument(
        "--discover",
        required=True,
        help="Path to Step 1 discovery report JSON file (required)",
    )
    score_parser.add_argument(
        "--probe",
        default=None,
        help="Path to Step 2 probe report JSON file (optional)",
    )
    score_parser.add_argument(
        "--portscan",
        default=None,
        help="Path to Step 3 portscan report JSON file (optional)",
    )
    score_parser.add_argument(
        "--inspect",
        default=None,
        help="Path to Step 4 inspect report JSON file (optional)",
    )
    score_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON score report (default: output)",
    )
    score_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: admin
    admin_parser = subparsers.add_parser(
        "admin",
        help="Administrative operations",
    )
    admin_subparsers = admin_parser.add_subparsers(dest="admin_command", required=True)
    admin_move = admin_subparsers.add_parser(
        "move-domain",
        help="Move a quarantined domain from legacy quarantine to a target organization",
    )
    admin_move.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain to move",
    )
    admin_move.add_argument(
        "--target-org-id",
        type=int,
        required=True,
        help="ID of the target customer organization",
    )

    admin_verify = admin_subparsers.add_parser(
        "verify-domain",
        help="Grant an operator override verification to a domain",
    )
    admin_verify.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain to verify",
    )
    admin_verify.add_argument(
        "--reason",
        type=str,
        required=True,
        help="Mandatory justification for operator verification override",
    )
    admin_verify.add_argument(
        "--expires-in-days",
        type=int,
        default=30,
        help="Duration in days before the override expires (default: 30, max: 90)",
    )

    admin_revoke = admin_subparsers.add_parser(
        "revoke-verification",
        help="Revoke domain verification and reset status to pending",
    )
    admin_revoke.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain whose verification will be revoked",
    )
    admin_revoke.add_argument(
        "--reason",
        type=str,
        required=True,
        help="Mandatory justification for revoking domain verification",
    )
    for name, help_text in (
        ("suspend-user", "Suspend an account (403 on every request; may stop org schedules)"),
        ("unsuspend-user", "Lift a suspension (schedules stay off until an owner re-enables)"),
    ):
        admin_account = admin_subparsers.add_parser(name, help=help_text)
        admin_account.add_argument(
            "--user-id", type=str, required=True, help="User ID (UUID) of the account"
        )
        admin_account.add_argument(
            "--reason",
            type=str,
            required=True,
            help="Operator-only justification (never shown to users or tenants)",
        )

    return parser


def handle_discover(domain_arg: str, output_dir_arg: str) -> int:
    """Execute the subdomain discovery and DNS resolution workflow.

    Args:
        domain_arg: The raw user-supplied target domain.
        output_dir_arg: Directory path to write the JSON report to.

    Returns:
        Exit code: 0 on success, 1 on validation error, 2 on crt.sh failure.
    """
    # 1. Input validation & normalization
    try:
        domain = validate_domain(domain_arg)
    except DomainValidationError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    start_mono = time.monotonic()
    scan_start_dt = datetime.now(UTC)
    scan_started_utc = scan_start_dt.isoformat()

    print(f"[*] Discovering subdomains for '{domain}'...")

    # 2. Query Certificate Transparency logs with fallback
    try:
        subdomains, source, fallback_reason, truncated = discover_subdomains(
            domain,
            crtsh_fetcher=fetch_crtsh_data,
        )
    except DiscoveryError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    total_found = len(subdomains)

    results: list[SubdomainResult] = []
    if total_found == 0:
        print("[*] 0 subdomains found.")
        resolved_count = 0
        unresolved_count = 0
    else:
        print(f"[*] Found {total_found} unique subdomains. Resolving DNS records...")
        # 3. Resolve DNS records concurrently
        results = resolve_subdomains_concurrently(subdomains)
        resolved_count = sum(1 for r in results if r.resolved)
        unresolved_count = total_found - resolved_count

    scan_finish_dt = datetime.now(UTC)
    scan_finished_utc = scan_finish_dt.isoformat()
    elapsed_seconds = round(time.monotonic() - start_mono, 2)

    # 4. Build report
    counts = {
        "total_discovered": total_found,
        "resolved": resolved_count,
        "unresolved": unresolved_count,
    }
    report = DiscoveryReport(
        domain=domain,
        scan_started_utc=scan_started_utc,
        scan_finished_utc=scan_finished_utc,
        source=source,
        fallback_reason=fallback_reason,
        truncated=truncated,
        counts=counts,
        results=results,
    )

    # 5. Save report to JSON file
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Format Windows-safe UTC timestamp with no colons (e.g. 20260929T041500Z)
    filename_ts = scan_start_dt.strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"{domain}_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    # 6. Print summary to user
    print("\n=== Discovery Summary ===")
    print(f"Domain:              {domain}")
    print(f"Source:              {source}")
    print(f"Subdomains Found:    {total_found}")
    print(f"Resolved (Active):   {resolved_count}")
    print(f"Unresolved:          {unresolved_count}")
    print(f"Scan Duration:       {elapsed_seconds}s")
    print(f"Report File:         {report_file}")

    return 0


def handle_probe(report_file_arg: str, authorized: bool, output_dir_arg: str) -> int:
    """Execute the active HTTP/HTTPS host probing workflow.

    Enforces authorization gate, validates discovery report input, performs
    concurrent probing against resolved hosts, and writes a probe report.

    Args:
        report_file_arg: Path to the Step 1 discovery report JSON file.
        authorized: User-supplied boolean confirmation of testing authorization.
        output_dir_arg: Target directory for the probe report.

    Returns:
        Exit code: 0 on success, 1 on authorization or validation error.
    """
    # 1. Load and validate discovery report as untrusted input
    try:
        report_data, domain, resolved_hosts, skipped_unresolved_count = load_and_validate_report(
            report_file_arg
        )
    except ReportValidationError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # 2. Authorization Gate (strictly enforced before any network requests)
    if not authorized:
        sys.stderr.write(
            f"Active probing sends requests to {domain}. Re-run with --authorized "
            "to confirm you own it or have written permission to test it.\n"
        )
        return 1

    start_mono = time.monotonic()
    probe_start_dt = datetime.now(UTC)
    probe_started_utc = probe_start_dt.isoformat()

    results: list[HostProbeResult] = []

    # 3. Probing execution
    if not resolved_hosts:
        print("[*] 0 resolved hosts to probe.")
    else:
        print(f"[*] Probing {len(resolved_hosts)} resolved hosts for '{domain}' (HTTPS/HTTP)...")
        results = probe_hosts_concurrently(resolved_hosts, domain, max_workers=10)

    probe_finish_dt = datetime.now(UTC)
    probe_finished_utc = probe_finish_dt.isoformat()
    elapsed_seconds = round(time.monotonic() - start_mono, 2)

    # 4. Statistical counts
    hosts_probed = sum(1 for r in results if r.status == HostProbeStatus.PROBED.value)
    https_live = sum(1 for r in results if r.https is not None and r.https.reachable)
    http_only = sum(
        1
        for r in results
        if (
            r.http is not None
            and r.http.reachable
            and not (r.https is not None and r.https.reachable)
        )
    )
    unreachable = sum(1 for r in results if r.status == HostProbeStatus.PROBED.value and not r.live)
    tls_invalid = sum(1 for r in results if r.https is not None and r.https.tls_valid is False)
    skipped_untrusted = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_UNTRUSTED.value
    )
    skipped_private_ip = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
    )

    counts = {
        "hosts_probed": hosts_probed,
        "https_live": https_live,
        "http_only": http_only,
        "unreachable": unreachable,
        "tls_invalid": tls_invalid,
        "skipped_untrusted": skipped_untrusted,
        "skipped_private_ip": skipped_private_ip,
        "skipped_unresolved": skipped_unresolved_count,
    }

    report_path = Path(report_file_arg)
    report = ProbeReport(
        domain=domain,
        source_report=str(report_path.name),
        probe_started_utc=probe_started_utc,
        probe_finished_utc=probe_finished_utc,
        counts=counts,
        results=results,
    )

    # 5. Save probe report
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename_ts = probe_start_dt.strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"{domain}_probe_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    # 6. Print summary
    print("\n=== Probe Summary ===")
    print(f"Domain:              {domain}")
    print(f"Hosts Probed:        {hosts_probed}")
    print(f"HTTPS Live:          {https_live}")
    print(f"HTTP Only:           {http_only}")
    print(f"Unreachable:         {unreachable}")
    print(f"TLS Invalid:         {tls_invalid}")
    print(f"Skipped Untrusted:   {skipped_untrusted}")
    print(f"Skipped Private IP:  {skipped_private_ip}")
    print(f"Skipped Unresolved:  {skipped_unresolved_count}")
    print(f"Scan Duration:       {elapsed_seconds}s")
    print(f"Report File:         {report_file}")

    # Print live hosts list
    live_hosts = [r for r in results if r.live]
    if live_hosts:
        print("\n=== Live Hosts ===")
        for host_res in live_hosts:
            active_url_res = (
                host_res.https if (host_res.https and host_res.https.reachable) else host_res.http
            )
            if active_url_res is not None:
                url_display = active_url_res.final_url or active_url_res.url
                code_display = active_url_res.status_code or "???"
                title_display = active_url_res.title or ""
                print(f"{url_display} [{code_display}] {title_display}".strip())

    return 0


def handle_portscan(report_file_arg: str, authorized: bool, output_dir_arg: str) -> int:
    """Execute the active TCP port scanning workflow.

    Enforces authorization gate, validates discovery report input, scans
    fixed TCP ports across resolved hosts, and writes a port scan report.

    Args:
        report_file_arg: Path to Step 1 discovery report JSON file.
        authorized: User confirmation of testing authorization.
        output_dir_arg: Target directory for the port scan report.

    Returns:
        Exit code: 0 on success, 1 on authorization or validation error.
    """
    # 1. Load and validate discovery report as untrusted input
    try:
        report_data, domain, resolved_hosts, skipped_unresolved_count = load_and_validate_report(
            report_file_arg
        )
    except ReportValidationError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # 2. Authorization Gate (strictly enforced before any network requests)
    if not authorized:
        sys.stderr.write(
            f"Active port scanning connects to {domain}. Re-run with --authorized "
            "to confirm you own it or have written permission to test it.\n"
        )
        return 1

    start_mono = time.monotonic()
    scan_start_dt = datetime.now(UTC)
    scan_started_utc = scan_start_dt.isoformat()

    results: list[HostPortScanResult] = []

    # 3. Port scanning execution
    if not resolved_hosts:
        print("[*] 0 resolved hosts to scan.")
    else:
        print(
            f"[*] Scanning common ports on {len(resolved_hosts)} resolved hosts for '{domain}'..."
        )
        results = run_port_scan(resolved_hosts, domain)

    scan_finish_dt = datetime.now(UTC)
    scan_finished_utc = scan_finish_dt.isoformat()
    elapsed_seconds = round(time.monotonic() - start_mono, 2)

    # 4. Statistical counts
    hosts_scanned = sum(1 for r in results if r.status == HostProbeStatus.PROBED.value)
    hosts_skipped = sum(1 for r in results if r.status != HostProbeStatus.PROBED.value)
    total_open_ports = sum(len(r.open_ports) for r in results)
    skipped_untrusted = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_UNTRUSTED.value
    )
    skipped_private_ip = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
    )
    skipped_at_scan_time = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_UNRESOLVED.value
    )
    total_skipped_unresolved = skipped_unresolved_count + skipped_at_scan_time

    counts = {
        "hosts_scanned": hosts_scanned,
        "hosts_skipped": hosts_skipped,
        "total_open_ports": total_open_ports,
        "skipped_untrusted": skipped_untrusted,
        "skipped_private_ip": skipped_private_ip,
        "skipped_unresolved": total_skipped_unresolved,
    }

    report_path = Path(report_file_arg)
    report = PortScanReport(
        domain=domain,
        source_report=str(report_path.name),
        scan_started_utc=scan_started_utc,
        scan_finished_utc=scan_finished_utc,
        port_list_used=DEFAULT_PORTS,
        counts=counts,
        results=results,
    )

    # 5. Save report to JSON file
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename_ts = scan_start_dt.strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"{domain}_portscan_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    # 6. Print summary
    print("\n=== Port Scan Summary ===")
    print(f"Domain:              {domain}")
    print(f"Hosts Scanned:       {hosts_scanned}")
    print(f"Hosts Skipped:       {hosts_skipped}")
    print(f"Total Open Ports:    {total_open_ports}")
    print(f"Skipped Untrusted:   {skipped_untrusted}")
    print(f"Skipped Private IP:  {skipped_private_ip}")
    print(f"Skipped Unresolved:  {total_skipped_unresolved}")
    print(f"Scan Duration:       {elapsed_seconds}s")
    print(f"Report File:         {report_file}")

    # 7. Print open ports & risk flags per host
    print("\n=== Open Ports & Risk Flags ===")
    scanned_hosts = [r for r in results if r.status == HostProbeStatus.PROBED.value]
    if not scanned_hosts or total_open_ports == 0:
        print("No open ports discovered.")
    else:
        for host_res in scanned_hosts:
            if not host_res.open_ports:
                continue
            print(f"[+] {host_res.subdomain}")
            for p in host_res.open_ports:
                banner_str = f" [Banner: {p.banner}]" if p.banner else ""
                print(f"    - {p.port}/{p.service_guess}{banner_str}")
            if host_res.risk_flags:
                flags_str = ", ".join(host_res.risk_flags)
                print(f"    ! Risk Flags: {flags_str}")

    return 0


def handle_inspect(report_file_arg: str, authorized: bool, output_dir_arg: str) -> int:
    """Execute the active TLS certificate and HTTP security headers inspection workflow.

    Args:
        report_file_arg: Path to Step 2 probe report JSON file.
        authorized: User confirmation of testing authorization.
        output_dir_arg: Target directory for the inspect report.

    Returns:
        Exit code: 0 on success, 1 on authorization or validation error.
    """
    # 1. Load and validate probe report as untrusted input
    try:
        report_data, domain, resolved_hosts, skipped_unresolved_count = load_and_validate_report(
            report_file_arg
        )
    except ReportValidationError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # 2. Authorization Gate (strictly enforced before any network requests)
    if not authorized:
        sys.stderr.write(
            f"Active inspection sends requests to {domain}. Re-run with --authorized "
            "to confirm you own it or have written permission to test it.\n"
        )
        return 1

    results_data = report_data.get("results", [])
    report_path = Path(report_file_arg)

    print(f"[*] Inspecting TLS and security headers for live HTTPS hosts of '{domain}'...")
    inspect_report = run_inspection(results_data, domain, report_path.name)

    # 3. Save report to JSON file
    start_dt = datetime.fromisoformat(inspect_report.inspect_started_utc)
    filename_ts = start_dt.strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / f"{domain}_inspect_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(inspect_report.to_dict(), f, indent=2)

    # 4. Print summary
    counts = inspect_report.counts
    print("\n=== Inspection Summary ===")
    print(f"Domain:              {domain}")
    print(f"Hosts Inspected:     {counts.get('hosts_inspected', 0)}")
    print(f"Valid Certificates:  {counts.get('certs_valid', 0)}")
    print(f"Expired Certs:       {counts.get('certs_expired', 0)}")
    print(f"Expiring Soon (<=30d): {counts.get('certs_expiring_soon', 0)}")
    print(f"Missing HSTS:        {counts.get('hosts_missing_hsts', 0)}")
    print(f"Skipped Not HTTPS:   {counts.get('skipped_not_https', 0)}")
    print(f"Skipped Untrusted:   {counts.get('skipped_untrusted', 0)}")
    print(f"Skipped Private IP:  {counts.get('skipped_private_ip', 0)}")
    print(f"Report File:         {report_file}")

    # 5. Print host findings
    print("\n=== Host Findings ===")
    probed_hosts = [r for r in inspect_report.results if r.status == HostProbeStatus.PROBED.value]
    if not probed_hosts:
        print("No live HTTPS hosts were inspected.")
    else:
        for hr in probed_hosts:
            print(f"[+] {hr.subdomain}")
            # Cert line
            if hr.cert is None:
                print("    - Cert: NOT AVAILABLE (unreachable)")
            else:
                c = hr.cert
                status_parts = []
                version_str = f", {c.tls_version}" if c.tls_version else ""
                if c.expired:
                    status_parts.append(f"EXPIRED{version_str}")
                elif c.not_yet_valid:
                    status_parts.append(f"NOT YET VALID{version_str}")
                elif c.is_trusted and not c.hostname_mismatch:
                    days_exp = int(c.days_until_expiry)
                    status_parts.append(f"VALID (expires in {days_exp} days{version_str})")
                elif not c.is_trusted:
                    err_msg = c.verify_error or "invalid CA"
                    status_parts.append(f"UNTRUSTED ({err_msg}{version_str})")

                if c.issuer_equals_subject:
                    status_parts.append("LIKELY SELF-SIGNED")
                if c.hostname_mismatch:
                    status_parts.append("HOSTNAME MISMATCH")
                if c.deprecated_tls:
                    status_parts.append(f"DEPRECATED TLS ({c.tls_version})")

                status_desc = ", ".join(status_parts) if status_parts else "UNKNOWN"
                print(f"    - Cert: {status_desc} [{c.source}]")

            # Headers line
            if hr.headers is None:
                print("    - Headers: NOT AVAILABLE (unreachable)")
            elif hr.headers.error:
                print(f"    - Headers: Error fetching headers ({hr.headers.error})")
            else:
                missing = hr.headers.missing_headers
                if missing:
                    print(f"    - Missing Headers: {', '.join(missing)}")
                else:
                    print("    - Missing Headers: None (all monitored headers present)")
                if hr.headers.hsts_weak:
                    print(f"    ! Weak HSTS: max-age is {hr.headers.hsts_max_age}s (< 180 days)")
                if hr.headers.server_disclosed or hr.headers.x_powered_by_disclosed:
                    disclosures = []
                    if hr.headers.server:
                        disclosures.append(f"Server: {hr.headers.server}")
                    if hr.headers.x_powered_by:
                        disclosures.append(f"X-Powered-By: {hr.headers.x_powered_by}")
                    print(f"    ! Disclosed: {', '.join(disclosures)}")

    return 0


def handle_score(
    discover_path: str,
    probe_path: str | None,
    portscan_path: str | None,
    inspect_path: str | None,
    output_dir_arg: str,
) -> int:
    """Execute risk scoring and multi-stage report aggregation.

    Args:
        discover_path: Path to Step 1 discovery report JSON.
        probe_path: Optional path to Step 2 probe report JSON.
        portscan_path: Optional path to Step 3 portscan report JSON.
        inspect_path: Optional path to Step 4 inspect report JSON.
        output_dir_arg: Directory to save the final JSON score report.

    Returns:
        Exit code: 0 on success, 1 on validation or write error.
    """
    try:
        report = score_domain_reports(
            discover_path=discover_path,
            probe_path=probe_path,
            portscan_path=portscan_path,
            inspect_path=inspect_path,
        )
    except ReportValidationError as rve:
        print(f"Error: {rve}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.debug("Unexpected scoring error: %s", exc, exc_info=True)
        print(f"Error: Failed to compute score report: {exc}", file=sys.stderr)
        return 1

    out_dir = Path(output_dir_arg)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    report_path = out_dir / f"{report.domain}_score_{ts}.json"

    try:
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
    except OSError as err:
        print(f"Error: Failed to write score report to {report_path}: {err}", file=sys.stderr)
        return 1

    # CLI Output Summary
    print()
    print("=" * 80)
    print(f"ASM RISK SCORE REPORT: {report.domain}")
    print("=" * 80)
    print(f"Domain Severity Band: {report.domain_band}")
    print(f"Total Domain Risk Score: {report.domain_score} pts")
    print(f"Inputs Evaluated: {', '.join(report.inputs_present)}")
    if report.counts.get("high_escalation"):
        print("(! Escalation note: >= 3 HIGH severity hosts identified across domain)")

    breakdown = (
        f"Hosts Breakdown: {report.counts['hosts_evaluated']} total "
        f"({report.counts['hosts_critical']} Critical, "
        f"{report.counts['hosts_high']} High, "
        f"{report.counts['hosts_medium']} Medium, "
        f"{report.counts['hosts_low']} Low, "
        f"{report.counts['hosts_info']} Info)"
    )
    print(breakdown)
    print(f"Saved score report to {report_path}")
    print("-" * 80)
    print("HOSTS (sorted worst-first):")

    for host in report.hosts:
        print(f"\n  [{host.band}] {host.subdomain} (Score: {host.score} pts)")
        if not host.findings:
            print("    - Clean: No security findings identified")
            continue

        for f in host.findings:
            port_str = f" [Port {f.port}]" if f.port is not None else ""
            print(f"    * [{f.tier}] {f.title} ({f.points} pts){port_str}")
            print(f"      Evidence: {f.evidence}")

    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    setup_logging(verbose=getattr(args, "verbose", False))

    if args.command == "discover":
        return handle_discover(args.domain, args.output_dir)
    if args.command == "probe":
        return handle_probe(args.report_file, args.authorized, args.output_dir)
    if args.command == "portscan":
        return handle_portscan(args.report_file, args.authorized, args.output_dir)
    if args.command == "inspect":
        return handle_inspect(args.report_file, args.authorized, args.output_dir)
    if args.command == "score":
        return handle_score(
            discover_path=args.discover,
            probe_path=args.probe,
            portscan_path=args.portscan,
            inspect_path=args.inspect,
            output_dir_arg=args.output_dir,
        )
    if args.command == "admin":
        from asm.admin import (
            move_domain,
            revoke_verification,
            suspend_user,
            unsuspend_user,
            verify_domain,
        )
        from asm.db.session import get_session_factory
        from asm.logredact import install_log_redaction

        install_log_redaction()
        factory = get_session_factory()
        with factory() as session:
            if args.admin_command == "move-domain":
                return move_domain(session, args.domain_id, args.target_org_id)
            elif args.admin_command == "verify-domain":
                return verify_domain(
                    session,
                    args.domain_id,
                    args.reason,
                    expires_in_days=args.expires_in_days,
                )
            elif args.admin_command == "revoke-verification":
                return revoke_verification(session, args.domain_id, args.reason)
            elif args.admin_command == "suspend-user":
                return suspend_user(session, args.user_id, args.reason)
            elif args.admin_command == "unsuspend-user":
                return unsuspend_user(session, args.user_id, args.reason)

    return 0


if __name__ == "__main__":
    sys.exit(main())
