"""Data models for ASM SaaS discovery, probe results, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class DNSStatus(StrEnum):
    """Enumeration of possible DNS resolution outcomes for a subdomain."""

    RESOLVED = "RESOLVED"
    NXDOMAIN = "NXDOMAIN"
    NO_ANSWER = "NO_ANSWER"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class HostProbeStatus(StrEnum):
    """Enumeration of possible outcomes when evaluating whether to probe a host."""

    PROBED = "PROBED"
    SKIPPED_UNTRUSTED = "SKIPPED_UNTRUSTED"
    SKIPPED_PRIVATE_IP = "SKIPPED_PRIVATE_IP"
    SKIPPED_UNRESOLVED = "SKIPPED_UNRESOLVED"
    SKIPPED_NOT_HTTPS = "SKIPPED_NOT_HTTPS"


class ProbeErrorType(StrEnum):
    """Categorization of network or protocol failures encountered during HTTP probing."""

    TIMEOUT = "TIMEOUT"
    CONNECT_ERROR = "CONNECT_ERROR"
    TLS_ERROR = "TLS_ERROR"
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    OTHER = "OTHER"


@dataclass
class SubdomainResult:
    """Represents a discovered subdomain and its DNS resolution status.

    Attributes:
        subdomain: The fully-qualified subdomain name (e.g. 'api.example.com').
        ip_addresses: List of resolved IPv4 and IPv6 addresses.
        status: DNS resolution status (from DNSStatus).
        resolved: True if at least one IP address was resolved, False otherwise.
    """

    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    status: str = DNSStatus.NO_ANSWER.value
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the SubdomainResult to a dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class DiscoveryReport:
    """Top-level report containing the results of a passive discovery scan.

    Attributes:
        domain: The root domain investigated.
        scan_started_utc: ISO 8601 UTC timestamp when scan started.
        scan_finished_utc: ISO 8601 UTC timestamp when scan completed.
        source: The passive intelligence source used (defaults to 'crt.sh').
        counts: Summary counts of discovered, resolved, and unresolved domains.
        results: Detailed list of SubdomainResult objects.
    """

    domain: str
    scan_started_utc: str
    scan_finished_utc: str
    source: str = "crt.sh"
    fallback_reason: str | None = None
    truncated: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    results: list[SubdomainResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the full report to a dictionary suitable for JSON export."""
        return {
            "domain": self.domain,
            "scan_started_utc": self.scan_started_utc,
            "scan_finished_utc": self.scan_finished_utc,
            "source": self.source,
            "fallback_reason": self.fallback_reason,
            "truncated": self.truncated,
            "counts": self.counts,
            "results": [result.to_dict() for result in self.results],
        }


@dataclass
class RedirectHop:
    """Records an individual redirect step encountered during URL probing."""

    url: str
    status_code: int
    out_of_scope: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert redirect hop to dictionary."""
        return asdict(self)


@dataclass
class UrlProbeResult:
    """Outcome of probing a single URL (HTTPS or HTTP) for a host.

    Attributes:
        url: The initial URL targeted (e.g. 'https://api.example.com/').
        reachable: True if an HTTP response was received (even error/redirect).
        status_code: HTTP status code returned (e.g. 200, 301, 404, 500).
        final_url: The URL reached after following in-scope redirects.
        redirect_chain: Sequence of followed redirect hops.
        title: Extracted HTML <title> tag text (if Content-Type is text/html).
        server: Value of the 'Server' response header.
        x_powered_by: Value of the 'X-Powered-By' response header.
        content_type: Value of the 'Content-Type' response header.
        response_time_ms: Round-trip time in milliseconds.
        error_type: Categorized failure reason (from ProbeErrorType).
        error_message: Detailed error message or reason.
        tls_valid: Certificate validity (True=valid, False=cert verification error, None=HTTP).
    """

    url: str
    reachable: bool = False
    status_code: int | None = None
    final_url: str | None = None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    title: str | None = None
    server: str | None = None
    x_powered_by: str | None = None
    content_type: str | None = None
    response_time_ms: float | None = None
    error_type: str | None = None
    error_message: str | None = None
    tls_valid: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert URL probe result to dictionary."""
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "redirect_chain": [hop.to_dict() for hop in self.redirect_chain],
            "title": self.title,
            "server": self.server,
            "x_powered_by": self.x_powered_by,
            "content_type": self.content_type,
            "response_time_ms": self.response_time_ms,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "tls_valid": self.tls_valid,
        }


@dataclass
class HostProbeResult:
    """Outcome of probing both HTTPS and HTTP endpoints for a single hostname.

    Attributes:
        subdomain: Hostname probed (e.g. 'admin.example.com').
        status: Host status (PROBED, SKIPPED_UNTRUSTED, SKIPPED_PRIVATE_IP, etc.).
        skip_reason: Explanation if the host was skipped.
        https: Probe result for the HTTPS endpoint.
        http: Probe result for the HTTP endpoint.
        live: True if either HTTPS or HTTP endpoint responded.
        preferred_url: The primary URL to access the service (HTTPS if live, else HTTP).
    """

    subdomain: str
    status: str = HostProbeStatus.PROBED.value
    skip_reason: str | None = None
    https: UrlProbeResult | None = None
    http: UrlProbeResult | None = None
    live: bool = False
    preferred_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert host probe result to dictionary."""
        return {
            "subdomain": self.subdomain,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "https": self.https.to_dict() if self.https is not None else None,
            "http": self.http.to_dict() if self.http is not None else None,
            "live": self.live,
            "preferred_url": self.preferred_url,
        }


@dataclass
class ProbeReport:
    """Top-level report containing the results of an active HTTP/HTTPS probe scan.

    Attributes:
        domain: Root domain probed.
        source_report: Path or filename of the Step 1 discovery report used as input.
        probe_started_utc: ISO 8601 UTC timestamp when scan started.
        probe_finished_utc: ISO 8601 UTC timestamp when scan finished.
        counts: Statistical counts of probed, live, and skipped hosts.
        results: Detailed list of HostProbeResult objects.
    """

    domain: str
    source_report: str
    probe_started_utc: str
    probe_finished_utc: str
    counts: dict[str, int] = field(default_factory=dict)
    results: list[HostProbeResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert probe report to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "source_report": self.source_report,
            "probe_started_utc": self.probe_started_utc,
            "probe_finished_utc": self.probe_finished_utc,
            "counts": self.counts,
            "results": [result.to_dict() for result in self.results],
        }


class PortStatus(StrEnum):
    """Classification of a TCP port connection attempt."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


@dataclass
class PortResult:
    """Outcome of probing a single TCP port on a host.

    Attributes:
        port: TCP port number (e.g. 22, 80, 3306).
        state: Port connection state (OPEN, CLOSED, FILTERED).
        service_guess: Presumed service name based on standard port assignment.
        banner: Sanitized banner string if captured, or None.
        risk_flags: Security risk tags associated with this port (e.g. DATABASE_EXPOSURE).
        response_time_ms: Round-trip connect time in milliseconds.
    """

    port: int
    state: str = PortStatus.FILTERED.value
    service_guess: str = "unknown (guess by port)"
    banner: str | None = None
    risk_flags: list[str] = field(default_factory=list)
    response_time_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert PortResult to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class HostPortScanResult:
    """Scan results for all target TCP ports on a single host.

    Attributes:
        subdomain: Hostname scanned.
        status: Host status (PROBED, SKIPPED_UNTRUSTED, SKIPPED_PRIVATE_IP, SKIPPED_UNRESOLVED).
        skip_reason: Explanation if the host was skipped.
        open_ports: Detailed results for open ports (service, banner, flags).
        closed_ports: List of closed port numbers.
        filtered_ports: List of filtered (timed out/dropped) port numbers.
        risk_flags: Summary of all risk flags triggered across open ports on this host.
    """

    subdomain: str
    status: str = HostProbeStatus.PROBED.value
    skip_reason: str | None = None
    open_ports: list[PortResult] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)
    filtered_ports: list[int] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert HostPortScanResult to dictionary for JSON export."""
        return {
            "subdomain": self.subdomain,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "risk_flags": self.risk_flags,
        }


@dataclass
class PortScanReport:
    """Top-level report containing the results of a TCP port scan.

    Attributes:
        domain: Root domain scanned.
        source_report: Discovery report filename used as input.
        scan_started_utc: ISO 8601 UTC timestamp when scan started.
        scan_finished_utc: ISO 8601 UTC timestamp when scan finished.
        port_list_used: List of ports scanned.
        counts: Summary counts of hosts and open ports.
        results: Detailed results for each host.
    """

    domain: str
    source_report: str
    scan_started_utc: str
    scan_finished_utc: str
    port_list_used: list[int] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    results: list[HostPortScanResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert PortScanReport to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "source_report": self.source_report,
            "scan_started_utc": self.scan_started_utc,
            "scan_finished_utc": self.scan_finished_utc,
            "port_list_used": self.port_list_used,
            "counts": self.counts,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class CertInfo:
    """Detailed information and security flags for a TLS certificate.

    Attributes:
        subject_cn: Common Name from the certificate subject.
        sans: List of DNS Subject Alternative Names.
        issuer: Formatted issuer distinguished name.
        not_before: ISO 8601 UTC timestamp of validity start.
        not_after: ISO 8601 UTC timestamp of validity end.
        days_until_expiry: Number of days until certificate expires.
        serial_hex: Hexadecimal string of certificate serial number.
        tls_version: Negotiated TLS protocol version (e.g. 'TLSv1.3').
        hostname_matches: True if the scanned hostname matches CN or SANs.
        is_trusted: True if the certificate validates against standard CA bundle.
        verify_error: Verification error message if not trusted.
        source: Inspection method used ('from_response' or 'from_socket').
        expired: True if current time is past not_after.
        not_yet_valid: True if current time is before not_before.
        issuer_equals_subject: True if issuer matches subject (indicates likely self-signed).
        hostname_mismatch: True if hostname does not match cert CN or SANs.
        expiring_soon: True if days_until_expiry <= 30 and not yet expired.
        deprecated_tls: True if negotiated TLS version is TLS 1.0 or 1.1.
    """

    subject_cn: str | None = None
    sans: list[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: float = 0.0
    serial_hex: str | None = None
    tls_version: str | None = None
    hostname_matches: bool = False
    is_trusted: bool = False
    verify_error: str | None = None
    source: str = "from_response"
    expired: bool = False
    not_yet_valid: bool = False
    issuer_equals_subject: bool = False
    hostname_mismatch: bool = False
    expiring_soon: bool = False
    deprecated_tls: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert CertInfo to dictionary for JSON export."""
        return asdict(self)


@dataclass
class HeaderInfo:
    """Security headers evaluation and information disclosure detection.

    Attributes:
        present_headers: Dictionary of monitored security headers found.
        missing_headers: List of monitored security headers that were absent.
        hsts_max_age: Parsed max-age value from Strict-Transport-Security.
        hsts_weak: True if HSTS is present but max-age < 15552000 (180 days).
        server: Value of Server header if disclosed.
        x_powered_by: Value of X-Powered-By header if disclosed.
        x_aspnet_version: Value of X-AspNet-Version header if disclosed.
        server_disclosed: True if Server header reveals software/version.
        x_powered_by_disclosed: True if X-Powered-By header is present.
        x_aspnet_version_disclosed: True if X-AspNet-Version header is present.
        error: Error message if headers could not be fetched.
    """

    present_headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    hsts_max_age: int | None = None
    hsts_weak: bool = False
    server: str | None = None
    x_powered_by: str | None = None
    x_aspnet_version: str | None = None
    server_disclosed: bool = False
    x_powered_by_disclosed: bool = False
    x_aspnet_version_disclosed: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert HeaderInfo to dictionary for JSON export."""
        return asdict(self)


@dataclass
class HostInspectResult:
    """Inspection outcome for a single host covering TLS certificate and headers.

    Attributes:
        subdomain: Hostname inspected.
        status: Inspection status (PROBED, SKIPPED_UNTRUSTED, etc.).
        skip_reason: Explanation if skipped.
        cert: Certificate inspection findings, or None if skipped/unreachable.
        headers: Header inspection findings, or None if skipped/unreachable.
    """

    subdomain: str
    status: str = HostProbeStatus.PROBED.value
    skip_reason: str | None = None
    cert: CertInfo | None = None
    headers: HeaderInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert HostInspectResult to dictionary for JSON export."""
        return {
            "subdomain": self.subdomain,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "cert": self.cert.to_dict() if self.cert is not None else None,
            "headers": self.headers.to_dict() if self.headers is not None else None,
        }


@dataclass
class InspectReport:
    """Top-level report containing TLS certificate and HTTP security header findings.

    Attributes:
        domain: Target base domain.
        source_report: Filename of the input probe report.
        inspect_started_utc: ISO 8601 UTC timestamp of inspection start.
        inspect_finished_utc: ISO 8601 UTC timestamp of inspection completion.
        counts: Summary statistics.
        results: Detailed results for each host.
    """

    domain: str
    source_report: str
    inspect_started_utc: str
    inspect_finished_utc: str
    counts: dict[str, int] = field(default_factory=dict)
    results: list[HostInspectResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert InspectReport to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "source_report": self.source_report,
            "inspect_started_utc": self.inspect_started_utc,
            "inspect_finished_utc": self.inspect_finished_utc,
            "counts": self.counts,
            "results": [r.to_dict() for r in self.results],
        }


class SeverityTier(StrEnum):
    """Categorization of security findings and risk severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """An individual security finding discovered on a target host.

    Attributes:
        id: Unique identifier for the finding type (e.g. 'PORT_EXPOSED_DB').
        title: Human-readable short title.
        tier: Severity tier (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        points: Heuristic numerical risk score assigned to this finding.
        source: Source report stage ('discover', 'probe', 'portscan', 'inspect').
        host: Hostname where the finding was detected.
        port: Relevant TCP port number, or None if host/domain level.
        evidence: Concrete proof and observation string supporting the finding.
        why_it_matters: Plain-English explanation of security impact.
    """

    id: str
    title: str
    tier: str
    points: int
    source: str
    host: str
    port: int | None = None
    evidence: str = ""
    why_it_matters: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert Finding to dictionary for JSON export."""
        return asdict(self)


@dataclass
class HostScore:
    """Aggregated risk score and findings for a single target host.

    Attributes:
        subdomain: Hostname evaluated.
        score: Sum of points from all findings detected on this host.
        band: Host severity band derived from the worst finding tier.
        findings: List of individual findings for this host.
    """

    subdomain: str
    score: int = 0
    band: str = SeverityTier.INFO.value
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert HostScore to dictionary for JSON export."""
        return {
            "subdomain": self.subdomain,
            "score": self.score,
            "band": self.band,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScoreReport:
    """Top-level report containing domain-wide risk scores and per-host findings.

    Attributes:
        domain: Target base domain.
        generated_utc: ISO 8601 UTC timestamp of score generation.
        inputs_present: List of report sources present ('discover', 'probe', etc.).
        domain_score: Sum of all host risk points.
        domain_band: Domain-wide severity band derived from host bands.
        counts: Summary statistics of findings by tier and host counts by band.
        hosts: List of HostScore entries sorted worst-first.
        domain_findings: Findings about the domain as a whole (e.g. LARGE_ATTACK_SURFACE),
            not tied to any one host, so they survive when the apex is not a host.
    """

    domain: str
    generated_utc: str
    inputs_present: list[str]
    domain_score: int
    domain_band: str
    counts: dict[str, int] = field(default_factory=dict)
    hosts: list[HostScore] = field(default_factory=list)
    domain_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert ScoreReport to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "generated_utc": self.generated_utc,
            "inputs_present": self.inputs_present,
            "domain_score": self.domain_score,
            "domain_band": self.domain_band,
            "counts": self.counts,
            "hosts": [h.to_dict() for h in self.hosts],
            "domain_findings": [f.to_dict() for f in self.domain_findings],
        }
