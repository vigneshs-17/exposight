"""Scanner execution runner and protocol for Exposight background worker."""

from datetime import UTC, datetime
from typing import Any, Protocol

from asm.discovery import discover_subdomains
from asm.headers_inspect import run_inspection
from asm.models import (
    DiscoveryReport,
    HostProbeStatus,
    PortScanReport,
    ProbeReport,
    SubdomainResult,
)
from asm.portscan import DEFAULT_PORTS, run_port_scan
from asm.prober import probe_hosts_concurrently
from asm.resolver import resolve_subdomains_concurrently
from asm.scoring import score_domain_payloads
from asm.validators import validate_domain
from asm.worker.exceptions import SecurityGateError


class IScannerRunner(Protocol):
    """Protocol for executing scan stages without shelling out to CLI."""

    def run_discover(self, domain: str) -> dict[str, Any]:
        """Execute stage 1: discovery via Certificate Transparency and DNS resolution."""
        ...

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        """Execute stage 2: active HTTP/HTTPS probing."""
        ...

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        """Execute stage 3: active TCP port scanning."""
        ...

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        """Execute stage 4: TLS certificates and security headers inspection."""
        ...

    def run_score(
        self,
        domain: str,
        discover_report: dict[str, Any],
        probe_report: dict[str, Any] | None,
        portscan_report: dict[str, Any] | None,
        inspect_report: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Execute stage 5: heuristic risk scoring and report aggregation."""
        ...


class DirectScannerRunner:
    """Production implementation invoking v1 scanner core directly in-process.

    Writes no files to disk; all intermediate and final reports are returned
    as in-memory dictionaries.
    """

    def run_discover(self, domain: str) -> dict[str, Any]:
        validated_domain = validate_domain(domain)
        scan_start_dt = datetime.now(UTC)
        scan_started_utc = scan_start_dt.isoformat()

        subdomains, source, fallback_reason, truncated = discover_subdomains(validated_domain)
        total_found = len(subdomains)

        results: list[SubdomainResult] = []
        if total_found == 0:
            resolved_count = 0
            unresolved_count = 0
        else:
            results = resolve_subdomains_concurrently(subdomains)
            resolved_count = sum(1 for r in results if r.resolved)
            unresolved_count = total_found - resolved_count

        scan_finish_dt = datetime.now(UTC)
        scan_finished_utc = scan_finish_dt.isoformat()

        counts = {
            "total_discovered": total_found,
            "resolved": resolved_count,
            "unresolved": unresolved_count,
        }
        report = DiscoveryReport(
            domain=validated_domain,
            scan_started_utc=scan_started_utc,
            scan_finished_utc=scan_finished_utc,
            source=source,
            fallback_reason=fallback_reason,
            truncated=truncated,
            counts=counts,
            results=results,
        )
        return report.to_dict()

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError(
                f"Target domain '{domain}' is not authorized for active probing."
            )

        probe_start_dt = datetime.now(UTC)
        probe_started_utc = probe_start_dt.isoformat()

        raw_results = discover_report.get("results", [])
        resolved_hosts = [
            r["subdomain"] for r in raw_results if r.get("resolved") and r.get("subdomain")
        ]
        skipped_unresolved_count = discover_report.get("counts", {}).get("unresolved", 0)

        results = probe_hosts_concurrently(resolved_hosts, domain, max_workers=10)
        probe_finish_dt = datetime.now(UTC)
        probe_finished_utc = probe_finish_dt.isoformat()

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
        unreachable = sum(
            1 for r in results if r.status == HostProbeStatus.PROBED.value and not r.live
        )
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

        report = ProbeReport(
            domain=domain,
            source_report="discover_report",
            probe_started_utc=probe_started_utc,
            probe_finished_utc=probe_finished_utc,
            counts=counts,
            results=results,
        )
        return report.to_dict()

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError(
                f"Target domain '{domain}' is not authorized for active port scanning."
            )

        scan_start_dt = datetime.now(UTC)
        scan_started_utc = scan_start_dt.isoformat()

        raw_results = discover_report.get("results", [])
        resolved_hosts = [
            r["subdomain"] for r in raw_results if r.get("resolved") and r.get("subdomain")
        ]
        skipped_unresolved_count = discover_report.get("counts", {}).get("unresolved", 0)

        results = run_port_scan(resolved_hosts, domain)
        scan_finish_dt = datetime.now(UTC)
        scan_finished_utc = scan_finish_dt.isoformat()

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

        report = PortScanReport(
            domain=domain,
            source_report="discover_report",
            scan_started_utc=scan_started_utc,
            scan_finished_utc=scan_finished_utc,
            port_list_used=DEFAULT_PORTS,
            counts=counts,
            results=results,
        )
        return report.to_dict()

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError(
                f"Target domain '{domain}' is not authorized for active inspection."
            )

        results_data = probe_report.get("results", [])
        inspect_report = run_inspection(
            results_data, domain, source_report_name="probe_report"
        )
        return inspect_report.to_dict()

    def run_score(
        self,
        domain: str,
        discover_report: dict[str, Any],
        probe_report: dict[str, Any] | None,
        portscan_report: dict[str, Any] | None,
        inspect_report: dict[str, Any] | None,
    ) -> dict[str, Any]:
        disc_results = discover_report.get("results", [])
        probe_results = probe_report.get("results") if probe_report else None
        portscan_results = portscan_report.get("results") if portscan_report else None
        inspect_results = inspect_report.get("results") if inspect_report else None

        score_rep = score_domain_payloads(
            target_domain=domain,
            disc_results=disc_results,
            probe_results=probe_results,
            portscan_results=portscan_results,
            inspect_results=inspect_results,
        )
        return score_rep.to_dict()
