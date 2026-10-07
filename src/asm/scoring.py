"""Risk scoring and multi-stage report aggregation engine for Exposight.

Evaluates security findings from discovery, HTTP probing, TCP port scanning,
and TLS/headers inspection to produce defensive risk scores per host and
domain-wide.

The scoring model is a transparent heuristic severity model for triage.
It is NOT CVSS and does NOT guarantee exploitability.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from typing import Any

from asm.models import Finding, HostScore, ScoreReport, SeverityTier
from asm.scan_common import load_and_validate_generic_report

logger = logging.getLogger(__name__)

# Attack surface scale threshold
LARGE_ATTACK_SURFACE_THRESHOLD = 10
# Domain escalation threshold for multiple high-risk hosts
DOMAIN_HIGH_ESCALATION_THRESHOLD = 3


@dataclass(frozen=True)
class FindingDef:
    """Definition and static metadata for a cataloged security finding.

    Attributes:
        id: Unique identifier for the finding type.
        title: Short human-readable title.
        tier: Severity tier (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        points: Heuristic numerical risk score.
        why_it_matters: Security impact explanation.
    """

    id: str
    title: str
    tier: SeverityTier
    points: int
    why_it_matters: str


# ==============================================================================
# CENTRAL FINDING DEFINITIONS TABLE
# Defined in one place: easily auditable, consistent, and defensible.
# ==============================================================================
FINDING_DEFINITIONS: dict[str, FindingDef] = {
    # CRITICAL Tier: Confirmed reachable services with active remote banners
    "PORT_CONFIRMED_DB": FindingDef(
        id="PORT_CONFIRMED_DB",
        title="Confirmed Exposed Database Service",
        tier=SeverityTier.CRITICAL,
        points=10,
        why_it_matters=(
            "Exposed database service responded with an active banner directly on the "
            "public internet, indicating immediate risk of authentication bypass or data leak."
        ),
    ),
    # HIGH Tier: Exposed sensitive administrative ports or invalid TLS trust
    "PORT_EXPOSED_DB": FindingDef(
        id="PORT_EXPOSED_DB",
        title="Exposed Database Port",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Database port (3306, 5432, or 6379) is open to the public internet, "
            "inviting unauthorized access attempts and brute force attacks."
        ),
    ),
    "PORT_RDP_OPEN": FindingDef(
        id="PORT_RDP_OPEN",
        title="Exposed Remote Desktop (RDP)",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Exposed Windows Remote Desktop Protocol (RDP) on port 3389 is a primary "
            "attack vector for ransomware and credential brute forcing."
        ),
    ),
    "PORT_SMB_OPEN": FindingDef(
        id="PORT_SMB_OPEN",
        title="Exposed SMB File Sharing",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Exposed Server Message Block (SMB) on port 445 is historically vulnerable "
            "to remote code execution worms and lateral network movement."
        ),
    ),
    "PORT_TELNET_OPEN": FindingDef(
        id="PORT_TELNET_OPEN",
        title="Exposed Telnet Service",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Legacy Telnet service on port 23 transmits session data and credentials "
            "in cleartext and indicates outdated system administration."
        ),
    ),
    "TLS_CERT_EXPIRED": FindingDef(
        id="TLS_CERT_EXPIRED",
        title="Expired TLS Certificate",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Expired certificate triggers browser security warnings, blocks access, "
            "and prevents secure encrypted communication."
        ),
    ),
    "TLS_CERT_NOT_YET_VALID": FindingDef(
        id="TLS_CERT_NOT_YET_VALID",
        title="Not-Yet-Valid TLS Certificate",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Certificate validity start date is in the future; connecting clients "
            "will reject the connection as invalid."
        ),
    ),
    "TLS_UNTRUSTED": FindingDef(
        id="TLS_UNTRUSTED",
        title="Untrusted Certificate Authority",
        tier=SeverityTier.HIGH,
        points=7,
        why_it_matters=(
            "Certificate failed validation against public CA trust stores, exposing "
            "users to potential man-in-the-middle interception."
        ),
    ),
    # MEDIUM Tier: Cryptographic weaknesses, configuration mismatches, plaintext services
    "TLS_SELF_SIGNED": FindingDef(
        id="TLS_SELF_SIGNED",
        title="Self-Signed Certificate",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Certificate issuer matches subject. May be intentional on internal or "
            "development hosts, but lacks third-party verification on public assets."
        ),
    ),
    "TLS_HOSTNAME_MISMATCH": FindingDef(
        id="TLS_HOSTNAME_MISMATCH",
        title="Certificate Hostname Mismatch",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Domain name accessed does not match certificate SANs or Common Name, "
            "causing browser warnings and connection drops."
        ),
    ),
    "TLS_CERT_EXPIRING_SOON": FindingDef(
        id="TLS_CERT_EXPIRING_SOON",
        title="Certificate Expiring Soon (<=30 Days)",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Certificate expires in 30 days or less; requires scheduled renewal "
            "to prevent imminent service downtime."
        ),
    ),
    "TLS_DEPRECATED_VERSION": FindingDef(
        id="TLS_DEPRECATED_VERSION",
        title="Deprecated TLS Protocol (1.0 or 1.1)",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Legacy protocols lack modern ciphers and are vulnerable to cryptographic "
            "downgrade and chosen-ciphertext attacks."
        ),
    ),
    "PORT_PLAINTEXT_SERVICE": FindingDef(
        id="PORT_PLAINTEXT_SERVICE",
        title="Cleartext Protocol Service",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Unencrypted legacy protocol (FTP/SMTP/POP3/IMAP) transmits credentials "
            "and sensitive data across the network in cleartext."
        ),
    ),
    "HTTP_NO_HTTPS": FindingDef(
        id="HTTP_NO_HTTPS",
        title="HTTP Only (No HTTPS Available)",
        tier=SeverityTier.MEDIUM,
        points=4,
        why_it_matters=(
            "Host responds to plaintext HTTP on port 80 but HTTPS is unreachable "
            "or broken, leaving all user traffic unencrypted."
        ),
    ),
    # LOW Tier: Missing security headers and information disclosure
    "HEADER_MISSING_HSTS": FindingDef(
        id="HEADER_MISSING_HSTS",
        title="Missing Strict-Transport-Security (HSTS)",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "Absence of HSTS header allows opportunistic downgrade attacks (SSL-stripping) "
            "when users initiate unencrypted HTTP requests."
        ),
    ),
    "HEADER_WEAK_HSTS": FindingDef(
        id="HEADER_WEAK_HSTS",
        title="Weak HSTS Max-Age Duration",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "HSTS max-age is below the recommended 180-day minimum (15,552,000 seconds), "
            "reducing duration of enforced HTTPS protection."
        ),
    ),
    "HEADER_MISSING_CSP": FindingDef(
        id="HEADER_MISSING_CSP",
        title="Missing Content-Security-Policy (CSP)",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "Lack of Content-Security-Policy increases client vulnerability to "
            "cross-site scripting (XSS) and unauthorized resource loading."
        ),
    ),
    "HEADER_MISSING_X_FRAME_OPTIONS": FindingDef(
        id="HEADER_MISSING_X_FRAME_OPTIONS",
        title="Missing Clickjacking Defense (X-Frame-Options)",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "Without X-Frame-Options or CSP frame-ancestors, the site can be embedded "
            "within malicious frames for UI redressing attacks."
        ),
    ),
    "HEADER_MISSING_X_CONTENT_TYPE": FindingDef(
        id="HEADER_MISSING_X_CONTENT_TYPE",
        title="Missing MIME Sniffing Protection",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "Without 'X-Content-Type-Options: nosniff', browsers may attempt to MIME-sniff "
            "content and execute malicious script payloads."
        ),
    ),
    "HEADER_INFO_DISCLOSURE": FindingDef(
        id="HEADER_INFO_DISCLOSURE",
        title="Server Technology Disclosure",
        tier=SeverityTier.LOW,
        points=1,
        why_it_matters=(
            "Server or framework version headers reveal underlying software components, "
            "assisting attackers in finding known CVEs."
        ),
    ),
    # INFO Tier: General posture context and scale observations
    "LARGE_ATTACK_SURFACE": FindingDef(
        id="LARGE_ATTACK_SURFACE",
        title="Large External Attack Surface",
        tier=SeverityTier.INFO,
        points=0,
        why_it_matters=(
            "High number of active public assets increases configuration complexity "
            "and operational monitoring overhead."
        ),
    ),
}

# Numerical rankings for strict comparison
TIER_RANK: dict[str, int] = {
    SeverityTier.CRITICAL.value: 4,
    SeverityTier.HIGH.value: 3,
    SeverityTier.MEDIUM.value: 2,
    SeverityTier.LOW.value: 1,
    SeverityTier.INFO.value: 0,
}


def derive_host_band(findings: list[Finding]) -> str:
    """Determine host severity band based on its WORST finding tier.

    Rules (Rule 1):
    - Any CRITICAL finding -> CRITICAL
    - Else any HIGH finding -> HIGH
    - Else any MEDIUM finding -> MEDIUM
    - Else any LOW finding -> LOW
    - Else INFO (clean host / no findings)

    Args:
        findings: List of findings evaluated for this host.

    Returns:
        SeverityTier value string representing the host band.
    """
    if not findings:
        return SeverityTier.INFO.value

    highest_rank = -1
    worst_tier = SeverityTier.INFO.value

    for finding in findings:
        rank = TIER_RANK.get(finding.tier, 0)
        if rank > highest_rank:
            highest_rank = rank
            worst_tier = finding.tier

    return worst_tier


def derive_domain_band(host_scores: list[HostScore]) -> tuple[str, bool]:
    """Determine domain severity band based on the bands of its hosts.

    Rules (Rule 4):
    - Any CRITICAL host -> domain CRITICAL
    - Else any HIGH host -> HIGH (with >=3 HIGH hosts noted as escalation)
    - Else any MEDIUM host -> MEDIUM
    - Else any LOW host -> LOW
    - Else INFO

    Args:
        host_scores: Evaluated scores and bands for all hosts.

    Returns:
        Tuple of (domain_band, is_high_escalated).
    """
    if any(h.band == SeverityTier.CRITICAL.value for h in host_scores):
        return SeverityTier.CRITICAL.value, False

    high_hosts_count = sum(1 for h in host_scores if h.band == SeverityTier.HIGH.value)
    if high_hosts_count > 0:
        is_escalated = high_hosts_count >= DOMAIN_HIGH_ESCALATION_THRESHOLD
        return SeverityTier.HIGH.value, is_escalated

    if any(h.band == SeverityTier.MEDIUM.value for h in host_scores):
        return SeverityTier.MEDIUM.value, False

    if any(h.band == SeverityTier.LOW.value for h in host_scores):
        return SeverityTier.LOW.value, False

    return SeverityTier.INFO.value, False


def create_finding(
    finding_id: str,
    host: str,
    source: str,
    evidence: str,
    port: int | None = None,
) -> Finding:
    """Instantiate a Finding dataclass backed by the central definitions table.

    Args:
        finding_id: Key matching FINDING_DEFINITIONS.
        host: Target subdomain.
        source: Report source ('discover', 'probe', 'portscan', 'inspect').
        evidence: Concrete proof string.
        port: Optional port number.

    Returns:
        Populated Finding instance.
    """
    definition = FINDING_DEFINITIONS[finding_id]
    return Finding(
        id=definition.id,
        title=definition.title,
        tier=definition.tier.value,
        points=definition.points,
        source=source,
        host=host,
        port=port,
        evidence=evidence,
        why_it_matters=definition.why_it_matters,
    )


def evaluate_probe_findings(probe_results: list[dict[str, Any]]) -> dict[str, list[Finding]]:
    """Evaluate findings from HTTP/HTTPS probe results.

    Args:
        probe_results: Host entries from Step 2 probe report.

    Returns:
        Dictionary mapping subdomain to list of probe findings.
    """
    findings_by_host: dict[str, list[Finding]] = {}

    for entry in probe_results:
        host = entry.get("subdomain")
        if not host:
            continue

        host_findings: list[Finding] = []
        status = entry.get("status")
        https_info = entry.get("https") or {}
        http_info = entry.get("http") or {}

        if status == "PROBED":
            http_reachable = http_info.get("reachable") is True
            https_reachable = https_info.get("reachable") is True

            # Finding: Live host reachable on HTTP only (no HTTPS)
            if http_reachable and not https_reachable:
                evidence = (
                    f"HTTP (port 80) is reachable with status {http_info.get('status_code')}, "
                    f"but HTTPS (port 443) is unreachable or failed."
                )
                host_findings.append(
                    create_finding("HTTP_NO_HTTPS", host, "probe", evidence, port=80)
                )

        findings_by_host[host] = host_findings

    return findings_by_host


def evaluate_portscan_findings(portscan_results: list[dict[str, Any]]) -> dict[str, list[Finding]]:
    """Evaluate findings from TCP port scan results.

    Args:
        portscan_results: Host entries from Step 3 portscan report.

    Returns:
        Dictionary mapping subdomain to list of portscan findings.
    """
    findings_by_host: dict[str, list[Finding]] = {}

    for entry in portscan_results:
        host = entry.get("subdomain")
        if not host:
            continue

        host_findings: list[Finding] = []
        open_ports = entry.get("open_ports") or []

        for p_res in open_ports:
            port = p_res.get("port")
            state = p_res.get("state")
            banner = p_res.get("banner")
            service = p_res.get("service_guess", "unknown")

            if state != "OPEN" or not isinstance(port, int):
                continue

            # 1. Database ports (3306, 5432, 6379)
            if port in (3306, 5432, 6379):
                if banner and str(banner).strip():
                    evidence = (
                        f"Database port {port} ({service}) is OPEN with confirmed service banner: "
                        f"'{banner.strip()}'"
                    )
                    host_findings.append(
                        create_finding("PORT_CONFIRMED_DB", host, "portscan", evidence, port=port)
                    )
                else:
                    evidence = f"Database port {port} ({service}) is OPEN (no banner returned)."
                    host_findings.append(
                        create_finding("PORT_EXPOSED_DB", host, "portscan", evidence, port=port)
                    )

            # 2. Remote desktop (3389)
            elif port == 3389:
                evidence = f"Remote Desktop Protocol (RDP) port 3389 is OPEN ({service})."
                host_findings.append(
                    create_finding("PORT_RDP_OPEN", host, "portscan", evidence, port=port)
                )

            # 3. SMB file sharing (445)
            elif port == 445:
                evidence = f"Server Message Block (SMB) port 445 is OPEN ({service})."
                host_findings.append(
                    create_finding("PORT_SMB_OPEN", host, "portscan", evidence, port=port)
                )

            # 4. Telnet (23) - Rule 2 / Scope 3
            elif port == 23:
                evidence = f"Telnet service port 23 is OPEN ({service})."
                host_findings.append(
                    create_finding("PORT_TELNET_OPEN", host, "portscan", evidence, port=port)
                )

            # 5. Cleartext protocols (21, 25, 110, 143)
            elif port in (21, 25, 110, 143):
                evidence = f"Cleartext protocol port {port} ({service}) is OPEN."
                host_findings.append(
                    create_finding("PORT_PLAINTEXT_SERVICE", host, "portscan", evidence, port=port)
                )

        findings_by_host[host] = host_findings

    return findings_by_host


def evaluate_inspect_findings(inspect_results: list[dict[str, Any]]) -> dict[str, list[Finding]]:
    """Evaluate findings from TLS certificate and HTTP security header inspections.

    Args:
        inspect_results: Host entries from Step 4 inspect report.

    Returns:
        Dictionary mapping subdomain to list of inspection findings.
    """
    findings_by_host: dict[str, list[Finding]] = {}

    for entry in inspect_results:
        host = entry.get("subdomain")
        if not host:
            continue

        host_findings: list[Finding] = []
        cert = entry.get("cert")
        headers = entry.get("headers")

        if cert and isinstance(cert, dict):
            # Expired
            if cert.get("expired") is True:
                days = cert.get("days_until_expiry", 0)
                evidence = f"Certificate expired (expired by {abs(days):.1f} days)."
                host_findings.append(
                    create_finding("TLS_CERT_EXPIRED", host, "inspect", evidence, port=443)
                )

            # Not yet valid
            elif cert.get("not_yet_valid") is True:
                evidence = f"Certificate not yet valid (valid from {cert.get('not_before')})."
                host_findings.append(
                    create_finding("TLS_CERT_NOT_YET_VALID", host, "inspect", evidence, port=443)
                )

            # Self-signed / issuer_equals_subject (Rule 3: MEDIUM tier)
            elif cert.get("issuer_equals_subject") is True:
                evidence = (
                    f"Certificate is self-signed: issuer matches subject ({cert.get('issuer')})."
                )
                host_findings.append(
                    create_finding("TLS_SELF_SIGNED", host, "inspect", evidence, port=443)
                )

            # Untrusted CA (not self-signed and not expired)
            elif cert.get("is_trusted") is False:
                err_msg = cert.get("verify_error") or "Untrusted certificate authority"
                evidence = f"Certificate is untrusted: {err_msg}."
                host_findings.append(
                    create_finding("TLS_UNTRUSTED", host, "inspect", evidence, port=443)
                )

            # Hostname mismatch
            if cert.get("hostname_mismatch") is True:
                sans = cert.get("sans", [])
                evidence = (
                    f"Hostname mismatch: '{host}' does not match SANs {sans} "
                    f"or CN '{cert.get('subject_cn')}'."
                )
                host_findings.append(
                    create_finding("TLS_HOSTNAME_MISMATCH", host, "inspect", evidence, port=443)
                )

            # Expiring soon (and not expired)
            if cert.get("expiring_soon") is True and not cert.get("expired"):
                days = cert.get("days_until_expiry", 0)
                evidence = f"Certificate expires in {days:.1f} days (on {cert.get('not_after')})."
                host_findings.append(
                    create_finding("TLS_CERT_EXPIRING_SOON", host, "inspect", evidence, port=443)
                )

            # Deprecated TLS version
            if cert.get("deprecated_tls") is True:
                proto = cert.get("tls_version", "unknown")
                evidence = f"Negotiated obsolete protocol version '{proto}'."
                host_findings.append(
                    create_finding("TLS_DEPRECATED_VERSION", host, "inspect", evidence, port=443)
                )

        if headers and isinstance(headers, dict):
            missing = headers.get("missing_headers") or []

            # Missing HSTS
            if "Strict-Transport-Security" in missing:
                evidence = "Strict-Transport-Security (HSTS) header is not set."
                host_findings.append(
                    create_finding("HEADER_MISSING_HSTS", host, "inspect", evidence, port=443)
                )
            elif headers.get("hsts_weak") is True:
                max_age = headers.get("hsts_max_age")
                evidence = f"HSTS max-age is {max_age} seconds (< 15,552,000s recommended)."
                host_findings.append(
                    create_finding("HEADER_WEAK_HSTS", host, "inspect", evidence, port=443)
                )

            # Missing CSP
            if "Content-Security-Policy" in missing:
                evidence = "Content-Security-Policy header is not set."
                host_findings.append(
                    create_finding("HEADER_MISSING_CSP", host, "inspect", evidence, port=443)
                )

            # Missing X-Frame-Options
            if "X-Frame-Options" in missing:
                evidence = "X-Frame-Options header is not set."
                host_findings.append(
                    create_finding(
                        "HEADER_MISSING_X_FRAME_OPTIONS", host, "inspect", evidence, port=443
                    )
                )

            # Missing X-Content-Type-Options
            if "X-Content-Type-Options" in missing:
                evidence = "X-Content-Type-Options header is not set."
                host_findings.append(
                    create_finding(
                        "HEADER_MISSING_X_CONTENT_TYPE", host, "inspect", evidence, port=443
                    )
                )

            # Information disclosure
            disclosures = []
            if headers.get("server_disclosed") and headers.get("server"):
                disclosures.append(f"Server='{headers.get('server')}'")
            if headers.get("x_powered_by_disclosed") and headers.get("x_powered_by"):
                disclosures.append(f"X-Powered-By='{headers.get('x_powered_by')}'")
            if headers.get("x_aspnet_version_disclosed") and headers.get("x_aspnet_version"):
                disclosures.append(f"X-AspNet-Version='{headers.get('x_aspnet_version')}'")

            if disclosures:
                evidence = f"Server software banner disclosed: {', '.join(disclosures)}."
                host_findings.append(
                    create_finding("HEADER_INFO_DISCLOSURE", host, "inspect", evidence, port=443)
                )

        findings_by_host[host] = host_findings

    return findings_by_host


def score_domain_reports(
    discover_path: str,
    probe_path: str | None = None,
    portscan_path: str | None = None,
    inspect_path: str | None = None,
) -> ScoreReport:
    """Aggregate findings from all available scan stages and compute risk scores.

    Args:
        discover_path: Filepath to Step 1 discovery report JSON (required).
        probe_path: Optional filepath to Step 2 probe report JSON.
        portscan_path: Optional filepath to Step 3 portscan report JSON.
        inspect_path: Optional filepath to Step 4 inspect report JSON.

    Returns:
        ScoreReport containing aggregated scores, host band rankings, and findings.

    Raises:
        ReportValidationError: If any file is missing, invalid JSON, or has mismatched domains.
    """
    inputs_present = ["discover"]

    # 1. Load and validate discovery report
    _, target_domain, disc_results = load_and_validate_generic_report(
        discover_path, report_type="discover"
    )

    probe_results: list[dict[str, Any]] | None = None
    if probe_path:
        _, _, probe_results = load_and_validate_generic_report(
            probe_path, report_type="probe", expected_domain=target_domain
        )
        inputs_present.append("probe")

    portscan_results: list[dict[str, Any]] | None = None
    if portscan_path:
        _, _, portscan_results = load_and_validate_generic_report(
            portscan_path, report_type="portscan", expected_domain=target_domain
        )
        inputs_present.append("portscan")

    inspect_results: list[dict[str, Any]] | None = None
    if inspect_path:
        _, _, inspect_results = load_and_validate_generic_report(
            inspect_path, report_type="inspect", expected_domain=target_domain
        )
        inputs_present.append("inspect")

    return score_domain_payloads(
        target_domain=target_domain,
        disc_results=disc_results,
        probe_results=probe_results,
        portscan_results=portscan_results,
        inspect_results=inspect_results,
        inputs_present=inputs_present,
    )


def score_domain_payloads(
    target_domain: str,
    disc_results: list[dict[str, Any]],
    probe_results: list[dict[str, Any]] | None = None,
    portscan_results: list[dict[str, Any]] | None = None,
    inspect_results: list[dict[str, Any]] | None = None,
    inputs_present: list[str] | None = None,
) -> ScoreReport:
    """Aggregate findings from in-memory stage result payloads and compute risk scores."""
    if inputs_present is None:
        inputs_present = ["discover"]
        if probe_results is not None:
            inputs_present.append("probe")
        if portscan_results is not None:
            inputs_present.append("portscan")
        if inspect_results is not None:
            inputs_present.append("inspect")

    all_hosts: set[str] = set()
    for entry in disc_results:
        sub = entry.get("subdomain")
        if sub and isinstance(sub, str):
            all_hosts.add(sub.strip().lower())

    probe_findings_map: dict[str, list[Finding]] = {}
    if probe_results is not None:
        probe_findings_map = evaluate_probe_findings(probe_results)
        for h in probe_findings_map:
            all_hosts.add(h.lower())

    portscan_findings_map: dict[str, list[Finding]] = {}
    if portscan_results is not None:
        portscan_findings_map = evaluate_portscan_findings(portscan_results)
        for h in portscan_findings_map:
            all_hosts.add(h.lower())

    inspect_findings_map: dict[str, list[Finding]] = {}
    if inspect_results is not None:
        inspect_findings_map = evaluate_inspect_findings(inspect_results)
        for h in inspect_findings_map:
            all_hosts.add(h.lower())

    # Domain-wide observations are reported once, at domain level, whether or not
    # the apex itself is one of the hosts.
    domain_findings: list[Finding] = []
    if len(all_hosts) >= LARGE_ATTACK_SURFACE_THRESHOLD:
        evidence = f"Domain has {len(all_hosts)} discovered host assets."
        domain_findings.append(
            create_finding("LARGE_ATTACK_SURFACE", target_domain, "discover", evidence)
        )

    # 2. Compile findings per host
    evaluated_hosts: list[HostScore] = []

    for host in sorted(all_hosts):
        host_findings: list[Finding] = []
        host_findings.extend(probe_findings_map.get(host, []))
        host_findings.extend(portscan_findings_map.get(host, []))
        host_findings.extend(inspect_findings_map.get(host, []))

        # Sort findings within host: highest tier first, then points desc, then id
        host_findings.sort(
            key=lambda f: (TIER_RANK.get(f.tier, 0), f.points, f.id),
            reverse=True,
        )

        score_sum = sum(f.points for f in host_findings)
        band = derive_host_band(host_findings)

        evaluated_hosts.append(
            HostScore(
                subdomain=host,
                score=score_sum,
                band=band,
                findings=host_findings,
            )
        )

    # 3. Sort hosts: Worst band first, then highest score within band, then name
    evaluated_hosts.sort(
        key=lambda h: (-TIER_RANK.get(h.band, 0), -h.score, h.subdomain),
    )

    # 4. Derive domain band and summary counts
    domain_band, is_escalated = derive_domain_band(evaluated_hosts)
    total_domain_score = sum(h.score for h in evaluated_hosts) + sum(
        f.points for f in domain_findings
    )
    every_finding = [f for h in evaluated_hosts for f in h.findings] + domain_findings

    counts = {
        "hosts_evaluated": len(evaluated_hosts),
        "hosts_critical": sum(1 for h in evaluated_hosts if h.band == SeverityTier.CRITICAL.value),
        "hosts_high": sum(1 for h in evaluated_hosts if h.band == SeverityTier.HIGH.value),
        "hosts_medium": sum(1 for h in evaluated_hosts if h.band == SeverityTier.MEDIUM.value),
        "hosts_low": sum(1 for h in evaluated_hosts if h.band == SeverityTier.LOW.value),
        "hosts_info": sum(1 for h in evaluated_hosts if h.band == SeverityTier.INFO.value),
        "findings_critical": sum(
            1 for f in every_finding if f.tier == SeverityTier.CRITICAL.value
        ),
        "findings_high": sum(1 for f in every_finding if f.tier == SeverityTier.HIGH.value),
        "findings_medium": sum(1 for f in every_finding if f.tier == SeverityTier.MEDIUM.value),
        "findings_low": sum(1 for f in every_finding if f.tier == SeverityTier.LOW.value),
        "findings_info": sum(1 for f in every_finding if f.tier == SeverityTier.INFO.value),
        "high_escalation": 1 if is_escalated else 0,
    }

    now_utc = datetime.datetime.now(datetime.UTC).isoformat()

    return ScoreReport(
        domain=target_domain,
        generated_utc=now_utc,
        inputs_present=inputs_present,
        domain_score=total_domain_score,
        domain_band=domain_band,
        counts=counts,
        hosts=evaluated_hosts,
        domain_findings=domain_findings,
    )
