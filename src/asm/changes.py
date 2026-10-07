"""Change detection engine for Exposight.

Compares consecutive succeeded scan runs for the same domain to identify
attack surface exposure changes, security posture improvements, and
risk score band transitions.

The core comparison function `detect_changes` is a pure function that takes
baseline and new scan report dictionaries and returns a structured list of
change dictionaries with zero network or database dependencies.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from asm.models import Finding
from asm.scoring import (
    TIER_RANK,
    evaluate_inspect_findings,
    evaluate_portscan_findings,
    evaluate_probe_findings,
)

logger = logging.getLogger(__name__)

# Map finding definitions to change_type names
FINDING_TO_CHANGE_TYPE: dict[str, str] = {
    "PORT_CONFIRMED_DB": "PORT_NEWLY_OPEN",
    "PORT_EXPOSED_DB": "PORT_NEWLY_OPEN",
    "PORT_RDP_OPEN": "PORT_NEWLY_OPEN",
    "PORT_SMB_OPEN": "PORT_NEWLY_OPEN",
    "PORT_TELNET_OPEN": "PORT_NEWLY_OPEN",
    "PORT_PLAINTEXT_SERVICE": "PORT_NEWLY_OPEN",
    "HTTP_NO_HTTPS": "HTTPS_LOST",
    "TLS_CERT_EXPIRED": "CERTIFICATE_BECAME_EXPIRED",
    "TLS_CERT_NOT_YET_VALID": "CERTIFICATE_BECAME_UNTRUSTED",
    "TLS_SELF_SIGNED": "CERTIFICATE_SELF_SIGNED",
    "TLS_UNTRUSTED": "CERTIFICATE_BECAME_UNTRUSTED",
    "TLS_HOSTNAME_MISMATCH": "CERTIFICATE_HOSTNAME_MISMATCH",
    "TLS_CERT_EXPIRING_SOON": "CERTIFICATE_EXPIRING_SOON",
    "HEADER_MISSING_HSTS": "SECURITY_HEADER_REMOVED",
    # A weak HSTS header is still present: it was weakened, not removed. Changes stored
    # before v3.6c keep their old SECURITY_HEADER_REMOVED type and still display as-is.
    "HEADER_WEAK_HSTS": "SECURITY_HEADER_WEAKENED",
    "HEADER_MISSING_CSP": "SECURITY_HEADER_REMOVED",
    "HEADER_MISSING_X_FRAME_OPTIONS": "SECURITY_HEADER_REMOVED",
    "HEADER_MISSING_X_CONTENT_TYPE": "SECURITY_HEADER_REMOVED",
}

HEADER_NAME_MAP: dict[str, str] = {
    "HEADER_MISSING_HSTS": "Strict-Transport-Security",
    "HEADER_WEAK_HSTS": "Strict-Transport-Security",
    "HEADER_MISSING_CSP": "Content-Security-Policy",
    "HEADER_MISSING_X_FRAME_OPTIONS": "X-Frame-Options",
    "HEADER_MISSING_X_CONTENT_TYPE": "X-Content-Type-Options",
    "HEADER_INFO_DISCLOSURE": "Server-Technology",
}


def evaluate_removal_eligibility(
    baseline_discover: dict[str, Any],
    new_discover: dict[str, Any],
) -> tuple[bool, str | None]:
    """Determine whether subdomain removal detection is safe to perform.

    Removals are only evaluated if:
    1. Both baseline and new discovery reports used the same source (e.g. 'crt.sh').
    2. Neither report was truncated by pagination or entry limits.

    Missing 'source' defaults to 'crt.sh' (v1 compatibility).
    Missing 'truncated' defaults to False.

    Returns:
        (allow_removal, skip_reason)
    """
    base_source = baseline_discover.get("source", "crt.sh")
    new_source = new_discover.get("source", "crt.sh")
    base_truncated = baseline_discover.get("truncated", False) is True
    new_truncated = new_discover.get("truncated", False) is True

    if base_source != new_source:
        return False, f"Source mismatch ({base_source} vs {new_source})"
    if base_truncated and new_truncated:
        return False, "Baseline and new discovery reports were truncated"
    if base_truncated:
        return False, "Baseline discovery report was truncated"
    if new_truncated:
        return False, "New discovery report was truncated"

    return True, None


def _was_probed(inspect_entry: dict[str, Any] | None) -> bool:
    """Return True if an inspect result entry shows the host was actually inspected."""
    return bool(inspect_entry) and str(inspect_entry.get("status", "")).upper() == "PROBED"


def _get_inspect_detail(finding: Finding) -> str:
    """Derive detail string for an inspection finding."""
    if finding.id in HEADER_NAME_MAP:
        return HEADER_NAME_MAP[finding.id]
    return ""


def detect_changes(
    baseline_reports: dict[str, dict[str, Any]],
    new_reports: dict[str, dict[str, Any]],
    allow_removal: bool = True,
) -> list[dict[str, Any]]:
    """Pure comparison function to detect attack surface changes between two scans.

    Args:
        baseline_reports: Stage reports of the baseline succeeded scan.
        new_reports: Stage reports of the newly completed scan.
        allow_removal: If False, subdomain deletions will not be emitted.

    Returns:
        List of structured change dictionaries.
    """
    changes: list[dict[str, Any]] = []

    # 1. Determine observed_at timestamp from new score report (or fallback)
    score_report = new_reports.get("score") or {}
    observed_at_str = score_report.get("generated_utc")
    if not observed_at_str:
        for rep in ("inspect", "portscan", "probe", "discover"):
            if rep in new_reports and "scan_finished_utc" in new_reports[rep]:
                observed_at_str = new_reports[rep]["scan_finished_utc"]
                break

    if observed_at_str:
        try:
            observed_at = datetime.fromisoformat(observed_at_str)
        except Exception:
            observed_at = datetime.now(UTC)
    else:
        observed_at = datetime.now(UTC)

    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=UTC)

    # -------------------------------------------------------------------------
    # 2. Discover Stage Changes (Subdomain additions, removals, DNS changes)
    # -------------------------------------------------------------------------
    base_disc = baseline_reports.get("discover") or {}
    new_disc = new_reports.get("discover") or {}

    base_subs = {r["subdomain"]: r for r in base_disc.get("results", []) if "subdomain" in r}
    new_subs = {r["subdomain"]: r for r in new_disc.get("results", []) if "subdomain" in r}

    # New subdomains and DNS resolution changes
    for sub, n_entry in new_subs.items():
        if sub not in base_subs:
            changes.append({
                "change_type": "NEW_SUBDOMAIN",
                "category": "exposure",
                "severity": "INFO",
                "asset": sub,
                "detail": "",
                "evidence": "discover",
                "previous_state": None,
                "new_state": {
                    "status": n_entry.get("status"),
                    "resolved": n_entry.get("resolved"),
                },
                "observed_at": observed_at,
            })
        else:
            b_entry = base_subs[sub]
            b_stat = b_entry.get("status")
            n_stat = n_entry.get("status")
            b_res = b_entry.get("resolved", False) is True
            n_res = n_entry.get("resolved", False) is True

            # NXDOMAIN -> RESOLVED
            if b_stat == "NXDOMAIN" and n_stat == "RESOLVED" and n_res:
                changes.append({
                    "change_type": "NEWLY_RESOLVING",
                    "category": "exposure",
                    "severity": "INFO",
                    "asset": sub,
                    "detail": "",
                    "evidence": "discover",
                    "previous_state": {"status": b_stat, "resolved": b_res},
                    "new_state": {"status": n_stat, "resolved": n_res},
                    "observed_at": observed_at,
                })
            # RESOLVED -> NXDOMAIN (Definite stop; TIMEOUT / ERROR are ignored)
            elif b_stat == "RESOLVED" and b_res and n_stat == "NXDOMAIN" and not n_res:
                changes.append({
                    "change_type": "STOPPED_RESOLVING",
                    "category": "exposure",
                    "severity": "INFO",
                    "asset": sub,
                    "detail": "",
                    "evidence": "discover",
                    "previous_state": {"status": b_stat, "resolved": b_res},
                    "new_state": {"status": n_stat, "resolved": n_res},
                    "observed_at": observed_at,
                })

    # Removed subdomains (only if allow_removal is True)
    if allow_removal:
        for sub, b_entry in base_subs.items():
            if sub not in new_subs:
                changes.append({
                    "change_type": "REMOVED_SUBDOMAIN",
                    "category": "exposure",
                    "severity": "INFO",
                    "asset": sub,
                    "detail": "",
                    "evidence": "discover",
                    "previous_state": {
                        "status": b_entry.get("status"),
                        "resolved": b_entry.get("resolved"),
                    },
                    "new_state": None,
                    "observed_at": observed_at,
                })

    # -------------------------------------------------------------------------
    # 3. Diffing FINDINGS for Probe, Portscan, and Inspect
    # -------------------------------------------------------------------------
    new_probe_hosts = {
        r["subdomain"]: r
        for r in new_reports.get("probe", {}).get("results", [])
        if "subdomain" in r
    }
    base_probe_hosts = {
        r["subdomain"]: r
        for r in baseline_reports.get("probe", {}).get("results", [])
        if "subdomain" in r
    }

    base_port_hosts = {
        r["subdomain"]: r
        for r in baseline_reports.get("portscan", {}).get("results", [])
        if "subdomain" in r
    }
    new_port_hosts = {
        r["subdomain"]: r
        for r in new_reports.get("portscan", {}).get("results", [])
        if "subdomain" in r
    }

    base_insp_hosts = {
        r["subdomain"]: r
        for r in baseline_reports.get("inspect", {}).get("results", [])
        if "subdomain" in r
    }
    new_insp_hosts = {
        r["subdomain"]: r
        for r in new_reports.get("inspect", {}).get("results", [])
        if "subdomain" in r
    }

    base_probe_findings = evaluate_probe_findings(
        baseline_reports.get("probe", {}).get("results", [])
    )
    new_probe_findings = evaluate_probe_findings(
        new_reports.get("probe", {}).get("results", [])
    )

    new_port_findings = evaluate_portscan_findings(
        new_reports.get("portscan", {}).get("results", [])
    )

    base_inspect_findings = evaluate_inspect_findings(
        baseline_reports.get("inspect", {}).get("results", [])
    )
    new_inspect_findings = evaluate_inspect_findings(
        new_reports.get("inspect", {}).get("results", [])
    )

    # A. Probe Changes
    for host, n_findings in new_probe_findings.items():
        base_f_ids = {f.id for f in base_probe_findings.get(host, [])}
        for finding in n_findings:
            if finding.id == "HTTP_NO_HTTPS" and finding.id not in base_f_ids:
                # HTTPS can only be "lost" if the baseline really reached it over HTTPS.
                # New hosts and hosts unreachable in the baseline are not losses.
                base_https = (base_probe_hosts.get(host) or {}).get("https") or {}
                if base_https.get("reachable") is not True:
                    continue
                # Rule 5: HTTPS_LOST only on definite failure, never on a timeout
                https_probe = new_probe_hosts.get(host, {}).get("https") or {}
                error_type = https_probe.get("error_type")
                if error_type != "TIMEOUT":
                    changes.append({
                        "change_type": "HTTPS_LOST",
                        "category": "exposure",
                        "severity": "MEDIUM",
                        "asset": host,
                        "detail": "",
                        "evidence": "probe",
                        "previous_state": {"https_reachable": True},
                        "new_state": {"https_reachable": False, "error_type": error_type},
                        "observed_at": observed_at,
                    })

    # B. Portscan Changes
    all_port_hosts = set(base_port_hosts.keys()) | set(new_port_hosts.keys())
    for host in all_port_hosts:
        b_host_data = base_port_hosts.get(host, {})
        n_host_data = new_port_hosts.get(host, {})

        b_open_ports = {
            p["port"]
            for p in b_host_data.get("open_ports", [])
            if p.get("state") == "OPEN" and isinstance(p.get("port"), int)
        }
        n_open_ports_map = {
            p["port"]: p
            for p in n_host_data.get("open_ports", [])
            if p.get("state") == "OPEN" and isinstance(p.get("port"), int)
        }

        # Port newly open: in new open ports, not in baseline open ports
        for port, p_obj in n_open_ports_map.items():
            if port not in b_open_ports:
                # Determine severity from portscan finding if triggered, else INFO
                port_finding = next(
                    (f for f in new_port_findings.get(host, []) if f.port == port),
                    None,
                )
                severity = port_finding.tier if port_finding else "INFO"
                changes.append({
                    "change_type": "PORT_NEWLY_OPEN",
                    "category": "exposure",
                    "severity": severity,
                    "asset": host,
                    "detail": str(port),
                    "evidence": "portscan",
                    "previous_state": None,
                    "new_state": {
                        "port": port,
                        "state": "OPEN",
                        "service": p_obj.get("service_guess"),
                        "banner": p_obj.get("banner"),
                    },
                    "observed_at": observed_at,
                })

        # Port no longer open: was open in baseline, now closed in new
        # ONLY if host was evaluated (status == 'PROBED') and port is in closed_ports
        if str(n_host_data.get("status", "")).upper() == "PROBED":
            n_closed_ports = set(n_host_data.get("closed_ports", []))
            for port in b_open_ports:
                if port in n_closed_ports:
                    changes.append({
                        "change_type": "PORT_NO_LONGER_OPEN",
                        "category": "exposure",
                        "severity": "INFO",
                        "asset": host,
                        "detail": str(port),
                        "evidence": "portscan",
                        "previous_state": {"port": port, "state": "OPEN"},
                        "new_state": {"port": port, "state": "CLOSED"},
                        "observed_at": observed_at,
                    })

    # C. Inspect Changes (TLS & Headers)
    # 1. New findings present only in new scan.
    # Only hosts inspected successfully (PROBED) in BOTH scans are compared: a host that
    # is new, or was unreachable last time, has no baseline to have "lost" anything from.
    for host, n_findings in new_inspect_findings.items():
        if not (_was_probed(base_insp_hosts.get(host)) and _was_probed(new_insp_hosts.get(host))):
            continue
        base_findings_for_host = base_inspect_findings.get(host, [])
        base_f_keys = {(f.id, _get_inspect_detail(f)) for f in base_findings_for_host}
        for finding in n_findings:
            detail = _get_inspect_detail(finding)
            key = (finding.id, detail)
            if key not in base_f_keys:
                if finding.id == "HEADER_WEAK_HSTS" and any(
                    f.id == "HEADER_MISSING_HSTS" for f in base_findings_for_host
                ):
                    # Missing -> weak is an addition (reported as SECURITY_HEADER_ADDED
                    # below), not a weakening.
                    continue
                change_type = FINDING_TO_CHANGE_TYPE.get(finding.id)
                if change_type:
                    changes.append({
                        "change_type": change_type,
                        "category": "exposure",
                        "severity": finding.tier,
                        "asset": host,
                        "detail": detail,
                        "evidence": "inspect",
                        "previous_state": None,
                        "new_state": {"finding_id": finding.id, "evidence": finding.evidence},
                        "observed_at": observed_at,
                    })

    # 2. Baseline findings resolved in new scan
    # ONLY if host was successfully evaluated in new inspect (status == 'PROBED')
    for host, b_findings in base_inspect_findings.items():
        n_host_insp = new_insp_hosts.get(host)
        if not n_host_insp or str(n_host_insp.get("status", "")).upper() != "PROBED":
            # Host unreachable / skipped in new scan -> resolves no findings!
            continue

        new_f_keys = {
            (f.id, _get_inspect_detail(f)) for f in new_inspect_findings.get(host, [])
        }
        for b_finding in b_findings:
            detail = _get_inspect_detail(b_finding)
            key = (b_finding.id, detail)
            if key not in new_f_keys:
                if b_finding.id.startswith("HEADER_MISSING_"):
                    header_name = detail
                    present_headers = (
                        (n_host_insp.get("headers") or {}).get("present_headers") or {}
                    )
                    if header_name in present_headers:
                        changes.append({
                            "change_type": "SECURITY_HEADER_ADDED",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": host,
                            "detail": header_name,
                            "evidence": "inspect",
                            "previous_state": {"header": header_name, "status": "missing"},
                            "new_state": {
                                "header": header_name,
                                "status": "present",
                                "value": present_headers[header_name]
                                if isinstance(present_headers, dict)
                                else "",
                            },
                            "observed_at": observed_at,
                        })
                elif b_finding.id.startswith("TLS_"):
                    n_cert = n_host_insp.get("cert") or {}
                    if n_cert and not any(
                        f.id.startswith("TLS_") for f in new_inspect_findings.get(host, [])
                    ):
                        changes.append({
                            "change_type": "CERTIFICATE_CHANGED",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": host,
                            "detail": "",
                            "evidence": "inspect",
                            "previous_state": {"defect": b_finding.id},
                            "new_state": {
                                "not_after": n_cert.get("not_after"),
                                "issuer": n_cert.get("issuer"),
                            },
                            "observed_at": observed_at,
                        })

    # 3. Clean Certificate Rotation (Field rule when neither scan had TLS defects)
    for host, n_host_insp in new_insp_hosts.items():
        b_host_insp = base_insp_hosts.get(host)
        if not b_host_insp:
            continue
        if (
            str(n_host_insp.get("status", "")).upper() == "PROBED"
            and str(b_host_insp.get("status", "")).upper() == "PROBED"
        ):
            b_cert = b_host_insp.get("cert") or {}
            n_cert = n_host_insp.get("cert") or {}
            if b_cert and n_cert:
                b_tls_findings = [
                    f for f in base_inspect_findings.get(host, []) if f.id.startswith("TLS_")
                ]
                n_tls_findings = [
                    f for f in new_inspect_findings.get(host, []) if f.id.startswith("TLS_")
                ]
                if not b_tls_findings and not n_tls_findings:
                    if b_cert.get("issuer") != n_cert.get("issuer") and n_cert.get("issuer"):
                        changes.append({
                            "change_type": "CERTIFICATE_CHANGED",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": host,
                            "detail": "issuer",
                            "evidence": "inspect",
                            "previous_state": {"issuer": b_cert.get("issuer")},
                            "new_state": {"issuer": n_cert.get("issuer")},
                            "observed_at": observed_at,
                        })
                    elif (
                        b_cert.get("not_after") != n_cert.get("not_after")
                        and n_cert.get("not_after")
                    ):
                        changes.append({
                            "change_type": "CERTIFICATE_CHANGED",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": host,
                            "detail": "not_after",
                            "evidence": "inspect",
                            "previous_state": {"not_after": b_cert.get("not_after")},
                            "new_state": {"not_after": n_cert.get("not_after")},
                            "observed_at": observed_at,
                        })

    # -------------------------------------------------------------------------
    # 4. Score Stage Changes (Summary: Host and Domain Risk Bands)
    # -------------------------------------------------------------------------
    base_score = baseline_reports.get("score") or {}
    new_score = new_reports.get("score") or {}

    base_hosts = {
        h["subdomain"]: h for h in base_score.get("hosts", []) if "subdomain" in h
    }
    new_hosts = {
        h["subdomain"]: h for h in new_score.get("hosts", []) if "subdomain" in h
    }

    for host, n_host_score in new_hosts.items():
        if host in base_hosts:
            b_host_score = base_hosts[host]
            b_band = b_host_score.get("band", "INFO")
            n_band = n_host_score.get("band", "INFO")
            b_rank = TIER_RANK.get(b_band, 0)
            n_rank = TIER_RANK.get(n_band, 0)

            if n_rank > b_rank:
                changes.append({
                    "change_type": "HOST_RISK_BAND_INCREASED",
                    "category": "summary",
                    "severity": n_band,
                    "asset": host,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {"band": b_band, "score": b_host_score.get("score")},
                    "new_state": {"band": n_band, "score": n_host_score.get("score")},
                    "observed_at": observed_at,
                })
            elif n_rank < b_rank:
                changes.append({
                    "change_type": "HOST_RISK_BAND_DECREASED",
                    "category": "summary",
                    "severity": "INFO",
                    "asset": host,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {"band": b_band, "score": b_host_score.get("score")},
                    "new_state": {"band": n_band, "score": n_host_score.get("score")},
                    "observed_at": observed_at,
                })

    # Domain risk band
    b_domain_band = base_score.get("domain_band")
    n_domain_band = new_score.get("domain_band")
    domain_name = new_disc.get("domain") or new_score.get("domain", "")

    if b_domain_band and n_domain_band and domain_name:
        b_d_rank = TIER_RANK.get(b_domain_band, 0)
        n_d_rank = TIER_RANK.get(n_domain_band, 0)

        if n_d_rank > b_d_rank:
            changes.append({
                "change_type": "DOMAIN_RISK_BAND_INCREASED",
                "category": "summary",
                "severity": n_domain_band,
                "asset": domain_name,
                "detail": "",
                "evidence": "score",
                "previous_state": {
                    "band": b_domain_band,
                    "score": base_score.get("domain_score"),
                },
                "new_state": {
                    "band": n_domain_band,
                    "score": new_score.get("domain_score"),
                },
                "observed_at": observed_at,
            })
        elif n_d_rank < b_d_rank:
            changes.append({
                "change_type": "DOMAIN_RISK_BAND_DECREASED",
                "category": "summary",
                "severity": "INFO",
                "asset": domain_name,
                "detail": "",
                "evidence": "score",
                "previous_state": {
                    "band": b_domain_band,
                    "score": base_score.get("domain_score"),
                },
                "new_state": {
                    "band": n_domain_band,
                    "score": new_score.get("domain_score"),
                },
                "observed_at": observed_at,
            })

    # -------------------------------------------------------------------------
    # 5. Deduplicate by unique key (change_type, asset, detail)
    # -------------------------------------------------------------------------
    seen_keys: set[tuple[str, str, str]] = set()
    deduped_changes: list[dict[str, Any]] = []

    for change in changes:
        key = (change["change_type"], change["asset"], change["detail"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_changes.append(change)

    return deduped_changes
