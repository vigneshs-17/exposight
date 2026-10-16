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

    Note: allow_removal=True indicates the scan-level gate passed (non-truncated,
    matching source); actual REMOVED_SUBDOMAIN emission still strictly requires two
    consecutive qualifying absences matching each host's historical anchor source.
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


def _classify_https_probe_observation(host_data: dict[str, Any] | None) -> str:
    """Classify an HTTPS probe observation for bounded reachability change detection.

    Returns:
        'SUCCESS': Host was affirmatively PROBED and HTTPS endpoint was reachable.
        'QUALIFYING_FAILURE': Host was affirmatively PROBED, HTTP endpoint was reachable
            (satisfying HTTP_NO_HTTPS prerequisite), but HTTPS endpoint failed with a
            definite protocol/network failure ('CONNECT_ERROR' or 'TLS_ERROR').
        'UNKNOWN': Any missing host entry, non-PROBED status (e.g. SKIPPED_UNTRUSTED,
            SKIPPED_PRIVATE_IP, SKIPPED_UNRESOLVED, SKIPPED_NOT_HTTPS, SKIPPED_IPV6_ONLY),
            transient network timeout ('TIMEOUT'), redirect loop ('TOO_MANY_REDIRECTS'),
            unclassified error ('OTHER'), or general host unreachability (HTTP unreachable).
    """
    if not isinstance(host_data, dict):
        return "UNKNOWN"
    if str(host_data.get("status", "")).upper() != "PROBED":
        return "UNKNOWN"

    https_info = host_data.get("https")
    if not isinstance(https_info, dict):
        return "UNKNOWN"

    if https_info.get("reachable") is True:
        return "SUCCESS"

    # For a reachability loss to qualify, the host must still answer on HTTP
    # (consistent with HTTP_NO_HTTPS finding prerequisites; host-wide outages are UNKNOWN).
    http_info = host_data.get("http")
    if not isinstance(http_info, dict) or http_info.get("reachable") is not True:
        return "UNKNOWN"

    # Only definite connection or TLS errors qualify; timeouts, redirect loops, and other
    # inconclusive conditions are treated as UNKNOWN and reset the confirmation streak.
    error_type = https_info.get("error_type")
    if error_type in ("CONNECT_ERROR", "TLS_ERROR"):
        return "QUALIFYING_FAILURE"

    return "UNKNOWN"


def _is_valid_cert_data(cert: Any) -> bool:
    """Return True if cert dictionary contains non-empty certificate evidence."""
    return (
        isinstance(cert, dict)
        and bool(
            cert.get("issuer")
            or cert.get("not_after")
            or cert.get("subject_cn")
            or cert.get("serial_hex")
        )
    )


def _is_defect_remediated(finding_id: str, cert: dict[str, Any]) -> bool:
    """Return True only if cert contains affirmative evidence that the defect is resolved."""
    if not isinstance(cert, dict):
        return False
    if finding_id == "TLS_CERT_EXPIRED":
        return cert.get("expired") is False and bool(cert.get("not_after"))
    if finding_id == "TLS_CERT_NOT_YET_VALID":
        return cert.get("not_yet_valid") is False and bool(cert.get("not_before"))
    if finding_id == "TLS_CERT_EXPIRING_SOON":
        return (
            cert.get("expiring_soon") is False
            and cert.get("expired") is False
            and bool(cert.get("not_after"))
        )
    if finding_id in ("TLS_SELF_SIGNED", "TLS_UNTRUSTED"):
        return cert.get("is_trusted") is True and cert.get("issuer_equals_subject") is False
    if finding_id == "TLS_HOSTNAME_MISMATCH":
        return cert.get("hostname_matches") is True or (
            "hostname_mismatch" in cert and cert.get("hostname_mismatch") is False
        )
    if finding_id == "TLS_DEPRECATED_VERSION":
        return cert.get("deprecated_tls") is False and bool(cert.get("tls_version"))
    return False


def _find_latest_cert_for_defects(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
) -> tuple[int | None, dict[str, Any], dict[str, Any], list[Finding]] | None:
    """Search history window for certificate observation with completed security evaluation."""
    for scan_id, host_map, findings_map in history_indexed:
        h_data = host_map.get(host)
        if not h_data or str(h_data.get("status", "")).upper() != "PROBED":
            continue
        cert = h_data.get("cert")
        if not isinstance(cert, dict):
            continue
        host_findings = findings_map.get(host, [])
        has_tls_findings = any(f.id.startswith("TLS_") for f in host_findings)
        has_eval_fields = (
            "is_trusted" in cert
            or "expired" in cert
            or "hostname_matches" in cert
            or bool(cert.get("not_after"))
        )
        if has_tls_findings or has_eval_fields:
            tls_findings = [f for f in host_findings if f.id.startswith("TLS_")]
            return (scan_id, h_data, cert, tls_findings)
    return None


def _find_latest_clean_cert(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
) -> tuple[int | None, dict[str, Any], dict[str, Any]] | None:
    """Search history window for latest valid certificate observation with no TLS defects."""
    for scan_id, host_map, findings_map in history_indexed:
        h_data = host_map.get(host)
        if not h_data or str(h_data.get("status", "")).upper() != "PROBED":
            continue
        cert = h_data.get("cert")
        if not isinstance(cert, dict) or not _is_valid_cert_data(cert):
            continue
        host_findings = findings_map.get(host, [])
        tls_findings = [f for f in host_findings if f.id.startswith("TLS_")]
        if not tls_findings:
            return (scan_id, h_data, cert)
    return None


def _is_valid_header_data(headers: Any) -> bool:
    """Return True if headers dictionary contains valid security header evaluation."""
    return (
        isinstance(headers, dict)
        and headers.get("error") is None
        and (
            isinstance(headers.get("present_headers"), dict)
            or isinstance(headers.get("missing_headers"), list)
        )
    )


def _find_latest_header_observation(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
    header_name: str,
) -> tuple[int | None, str, dict[str, Any], list[Finding]] | None:
    """Search history window for the latest definite observation of a specific header.

    Returns:
        (scan_id, "PRESENT" | "MISSING", headers_dict, findings_for_host) or None.
    """
    header_lower = header_name.lower()
    for scan_id, host_map, findings_map in history_indexed:
        h_data = host_map.get(host)
        if not h_data or str(h_data.get("status", "")).upper() != "PROBED":
            continue
        headers = h_data.get("headers")
        if not isinstance(headers, dict) or headers.get("error") is not None:
            continue
        present = headers.get("present_headers")
        if isinstance(present, dict) and any(k.lower() == header_lower for k in present):
            return (scan_id, "PRESENT", headers, findings_map.get(host, []))
        missing = headers.get("missing_headers")
        if isinstance(missing, list) and any(m.lower() == header_lower for m in missing):
            return (scan_id, "MISSING", headers, findings_map.get(host, []))
        host_findings = findings_map.get(host, [])
        if any(
            f.id.startswith("HEADER_MISSING_")
            and HEADER_NAME_MAP.get(f.id, "").lower() == header_lower
            for f in host_findings
        ):
            return (scan_id, "MISSING", headers, host_findings)
    return None


def _find_latest_hsts_strength(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
) -> tuple[int | None, str] | None:
    """Search history window for the latest definite observation of HSTS strength.

    Returns:
        (scan_id, "STRONG" | "WEAK" | "MISSING") or None.
    """
    for scan_id, host_map, findings_map in history_indexed:
        h_data = host_map.get(host)
        if not h_data or str(h_data.get("status", "")).upper() != "PROBED":
            continue
        headers = h_data.get("headers")
        if not isinstance(headers, dict) or headers.get("error") is not None:
            continue
        host_findings = findings_map.get(host, [])
        if any(f.id == "HEADER_MISSING_HSTS" for f in host_findings):
            return (scan_id, "MISSING")
        missing = headers.get("missing_headers")
        if isinstance(missing, list) and any(
            m.lower() == "strict-transport-security" for m in missing
        ):
            return (scan_id, "MISSING")
        present = headers.get("present_headers")
        if isinstance(present, dict) and any(
            k.lower() == "strict-transport-security" for k in present
        ):
            if headers.get("hsts_weak") is True or any(
                f.id == "HEADER_WEAK_HSTS" for f in host_findings
            ):
                return (scan_id, "WEAK")
            return (scan_id, "STRONG")
    return None


def _find_latest_valid_cert(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
) -> tuple[int | None, dict[str, Any], dict[str, Any], list[Finding]] | None:
    """Search history window for the latest valid certificate observation."""
    return _find_latest_cert_for_defects(history_indexed, host)


def _find_latest_valid_header(
    history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ],
    host: str,
) -> tuple[int | None, dict[str, Any], dict[str, Any], list[Finding]] | None:
    """Search history window for the latest valid security header observation."""
    for scan_id, host_map, findings_map in history_indexed:
        h_data = host_map.get(host)
        if not h_data or str(h_data.get("status", "")).upper() != "PROBED":
            continue
        headers = h_data.get("headers")
        if _is_valid_header_data(headers):
            hdr_findings = [f for f in findings_map.get(host, []) if f.id.startswith("HEADER_")]
            return (scan_id, h_data, headers, hdr_findings)
    return None


def _get_inspect_detail(finding: Finding) -> str:
    """Derive detail string for an inspection finding."""
    if finding.id in HEADER_NAME_MAP:
        return HEADER_NAME_MAP[finding.id]
    return ""


def _find_latest_definite_port_observation(
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]]]],
    host: str,
    port: int,
) -> tuple[str, int | None, dict[str, Any] | None] | None:
    """Search up to 3 historical scans for the latest definite observation (OPEN or CLOSED).

    Uses pre-built per-scan host lookup maps to avoid repeated full-host searches.

    Returns:
        (state, scan_run_id, port_obj) where state is 'OPEN' or 'CLOSED'.
        Returns None if no definite observation exists in the bounded window.
    """
    for scan_id, host_map in history_indexed:
        host_data = host_map.get(host)
        if not host_data or str(host_data.get("status", "")).upper() != "PROBED":
            # Missing results, timeout, or unprobed host -> unknown observation
            continue

        # 1. Definite OPEN
        open_ports_list = host_data.get("open_ports")
        open_match = None
        if isinstance(open_ports_list, list):
            for p in open_ports_list:
                if isinstance(p, dict) and p.get("state") == "OPEN" and p.get("port") == port:
                    open_match = p
                    break

        if open_match is not None:
            return ("OPEN", scan_id, open_match)

        # 2. Definite CLOSED (only if not also reported OPEN)
        closed_ports_list = host_data.get("closed_ports")
        if isinstance(closed_ports_list, list) and port in closed_ports_list:
            return ("CLOSED", scan_id, None)

        # Port in filtered_ports or omitted -> unknown observation, check older scans
    return None


def detect_changes(
    baseline_reports: dict[str, dict[str, Any]],
    new_reports: dict[str, dict[str, Any]],
    allow_removal: bool = True,
    *,
    historical_baselines: list[dict[str, Any]] | None = None,
    baseline_scan_run_id: int | None = None,
) -> list[dict[str, Any]]:
    """Pure comparison function to detect attack surface changes between two scans.

    Args:
        baseline_reports: Stage reports of the baseline succeeded scan.
        new_reports: Stage reports of the newly completed scan.
        allow_removal: If False, subdomain deletions will not be emitted.
        historical_baselines: Optional list of up to 3 previous successful scans
            (ordered newest to oldest) with their reports and scan IDs.
        baseline_scan_run_id: Optional ID of the immediate baseline scan run.

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
    new_disc = new_reports.get("discover") or {}

    # Build indexed discovery history (up to 3 prior scans: S1, S2, S3)
    if historical_baselines is not None and len(historical_baselines) > 0:
        disc_history_entries = [
            entry
            if isinstance(entry, dict) and "reports" in entry
            else {"scan_run_id": None, "reports": entry}
            for entry in historical_baselines[:3]
        ]
    elif baseline_reports:
        disc_history_entries = [
            {"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}
        ]
    else:
        disc_history_entries = []

    # Indexed prior scans: list of (scan_id, source, truncated, is_empty, sub_map)
    disc_history_indexed: list[
        tuple[int | None, str, bool, bool, dict[str, dict[str, Any]]]
    ] = []
    for entry in disc_history_entries:
        s_id = entry.get("scan_run_id") or entry.get("id")
        rep = entry.get("reports") if "reports" in entry else entry
        d_rep = rep.get("discover") or {}
        s_src = d_rep.get("source", "crt.sh")
        s_trunc = bool(d_rep.get("truncated", False))
        s_results = d_rep.get("results")
        s_subs = (
            {r["subdomain"]: r for r in s_results if isinstance(r, dict) and "subdomain" in r}
            if isinstance(s_results, list)
            else {}
        )
        s_empty = len(s_subs) == 0
        disc_history_indexed.append((s_id, s_src, s_trunc, s_empty, s_subs))

    new_src = new_disc.get("source", "crt.sh")
    new_trunc = bool(new_disc.get("truncated", False))
    new_results = new_disc.get("results")
    new_subs = (
        {r["subdomain"]: r for r in new_results if isinstance(r, dict) and "subdomain" in r}
        if isinstance(new_results, list)
        else {}
    )
    new_empty = len(new_subs) == 0

    default_base_id = (
        disc_history_indexed[0][0]
        if disc_history_indexed and disc_history_indexed[0][0] is not None
        else baseline_scan_run_id
    )

    def _is_qualifying_absence(
        sub_name: str,
        scan_source: str,
        scan_truncated: bool,
        scan_empty: bool,
        scan_sub_map: dict[str, dict[str, Any]],
        anchor_source: str,
    ) -> bool:
        """Return True if scan is a non-empty, non-truncated absence matching anchor source."""
        return (
            sub_name not in scan_sub_map
            and not scan_empty
            and not scan_truncated
            and scan_source == anchor_source
        )

    # 2a. Additions (NEW_SUBDOMAIN) and DNS Resolution Changes
    for sub, n_entry in new_subs.items():
        # Find latest scan in history where sub was observed PRESENT
        last_present = None
        for idx, (s_id, s_src, _s_tr, _s_em, s_subs) in enumerate(disc_history_indexed):
            if sub in s_subs:
                last_present = (idx, s_id, s_src, s_subs[sub])
                break

        if last_present is None:
            # Case 1: First observed within available history
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
            # Case 2: Present in history.
            # Did it undergo confirmed absence immediately before new scan?
            pres_idx, _p_id, anchor_src, _p_entry = last_present
            s1_qualifies = (
                len(disc_history_indexed) >= 1
                and _is_qualifying_absence(
                    sub,
                    disc_history_indexed[0][1],
                    disc_history_indexed[0][2],
                    disc_history_indexed[0][3],
                    disc_history_indexed[0][4],
                    anchor_src,
                )
            )
            s2_qualifies = (
                len(disc_history_indexed) >= 2
                and _is_qualifying_absence(
                    sub,
                    disc_history_indexed[1][1],
                    disc_history_indexed[1][2],
                    disc_history_indexed[1][3],
                    disc_history_indexed[1][4],
                    anchor_src,
                )
            )

            if s1_qualifies and s2_qualifies and pres_idx >= 2:
                # Confirmed absent prior to new scan -> Genuine rediscovery
                s1_id = disc_history_indexed[0][0] or default_base_id
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
                    **({"baseline_scan_run_id": s1_id} if s1_id is not None else {}),
                })
            # Case 3: Noise recovery -> suppress duplicate addition

        # DNS resolution transitions (evaluated if present in immediate baseline S1)
        if disc_history_indexed and sub in disc_history_indexed[0][4]:
            b_entry = disc_history_indexed[0][4][sub]
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

    # 2b. Removals (REMOVED_SUBDOMAIN)
    if allow_removal and len(disc_history_indexed) >= 1:
        # Collect candidate subdomains that have an observed presence in history
        known_history_subs: dict[str, tuple[int | None, str, dict[str, Any]]] = {}
        for s_id, s_src, _s_tr, _s_em, s_subs in disc_history_indexed:
            for s_name, s_obj in s_subs.items():
                if s_name not in known_history_subs:
                    known_history_subs[s_name] = (s_id, s_src, s_obj)

        for sub, (p_id, anchor_src, p_entry) in known_history_subs.items():
            if sub in new_subs:
                continue

            s0_qualifies = _is_qualifying_absence(
                sub, new_src, new_trunc, new_empty, new_subs, anchor_src
            )
            if not s0_qualifies:
                continue

            s1_id, s1_src, s1_trunc, s1_empty, s1_subs = disc_history_indexed[0]
            s1_qualifies = _is_qualifying_absence(
                sub, s1_src, s1_trunc, s1_empty, s1_subs, anchor_src
            )
            if not s1_qualifies:
                continue

            # Prevent repeated removals: S2 must NOT have been a qualifying absence
            s2_already_confirmed = False
            if len(disc_history_indexed) >= 2:
                _s2_id, s2_src, s2_trunc, s2_empty, s2_subs = disc_history_indexed[1]
                if _is_qualifying_absence(sub, s2_src, s2_trunc, s2_empty, s2_subs, anchor_src):
                    s2_already_confirmed = True

            if not s2_already_confirmed:
                base_pres_id = p_id if p_id is not None else default_base_id
                change_dict = {
                    "change_type": "REMOVED_SUBDOMAIN",
                    "category": "exposure",
                    "severity": "INFO",
                    "asset": sub,
                    "detail": "",
                    "evidence": "discover",
                    "previous_state": {
                        "status": p_entry.get("status"),
                        "resolved": p_entry.get("resolved"),
                    },
                    "new_state": None,
                    "observed_at": observed_at,
                }
                if base_pres_id is not None:
                    change_dict["baseline_scan_run_id"] = base_pres_id
                changes.append(change_dict)

    # -------------------------------------------------------------------------
    # 3. Diffing FINDINGS for Probe, Portscan, and Inspect
    # -------------------------------------------------------------------------
    new_probe_hosts = {
        r["subdomain"]: r
        for r in new_reports.get("probe", {}).get("results", [])
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

    new_port_findings = evaluate_portscan_findings(
        new_reports.get("portscan", {}).get("results", [])
    )

    new_inspect_findings = evaluate_inspect_findings(
        new_reports.get("inspect", {}).get("results", [])
    )

    # A. Probe Changes (Bounded HTTPS-Loss Confirmation)
    # Build probe history window (up to 3 previous scans, newest to oldest: S1, S2, S3)
    if historical_baselines is not None and len(historical_baselines) > 0:
        probe_history_entries = [
            entry
            if isinstance(entry, dict) and "reports" in entry
            else {"scan_run_id": None, "reports": entry}
            for entry in historical_baselines[:3]
        ]
    elif baseline_reports:
        probe_history_entries = [
            {"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}
        ]
    else:
        probe_history_entries = []

    probe_history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]]]
    ] = []
    for entry in probe_history_entries:
        s_id = entry.get("scan_run_id") or entry.get("id")
        rep = entry.get("reports") if "reports" in entry else entry
        p_rep = rep.get("probe") or {}
        p_results = p_rep.get("results")
        p_hosts = (
            {r["subdomain"]: r for r in p_results if isinstance(r, dict) and "subdomain" in r}
            if isinstance(p_results, list)
            else {}
        )
        probe_history_indexed.append((s_id, p_hosts))

    default_probe_base_id = (
        probe_history_indexed[0][0]
        if probe_history_indexed and probe_history_indexed[0][0] is not None
        else baseline_scan_run_id
    )

    for host, n_host in new_probe_hosts.items():
        c_0 = _classify_https_probe_observation(n_host)
        if c_0 != "QUALIFYING_FAILURE":
            continue

        # Confirmation requires two consecutive qualifying failures (S0 and S1)
        if len(probe_history_indexed) < 1:
            continue
        s1_id, s1_hosts = probe_history_indexed[0]
        s1_host = s1_hosts.get(host)
        c_1 = _classify_https_probe_observation(s1_host)
        if c_1 != "QUALIFYING_FAILURE":
            continue

        # Two consecutive qualifying failures observed (S0 and S1).
        # Check for prior successful HTTPS reachability in the 3-prior-scan window (S2 or S3).
        # If never observed or expired from history, do not fabricate a confirmed transition.
        # If already confirmed at S1 (S1=F, S2=F, preceded by S3=SUCCESS), emit once and suppress.
        if len(probe_history_indexed) < 2:
            continue

        s2_id, s2_hosts = probe_history_indexed[1]
        s2_host = s2_hosts.get(host)
        c_2 = _classify_https_probe_observation(s2_host)

        confirmed = False
        prior_success_id: int | None = None

        if c_2 == "SUCCESS":
            # Transition: S2=SUCCESS -> S1=FAILURE -> S0=FAILURE
            confirmed = True
            prior_success_id = s2_id if s2_id is not None else default_probe_base_id
        elif c_2 == "UNKNOWN":
            # Check S3 for prior SUCCESS
            if len(probe_history_indexed) >= 3:
                s3_id, s3_hosts = probe_history_indexed[2]
                s3_host = s3_hosts.get(host)
                c_3 = _classify_https_probe_observation(s3_host)
                if c_3 == "SUCCESS":
                    # Transition: S3=SUCCESS -> S2=UNKNOWN -> S1=FAILURE -> S0=FAILURE
                    confirmed = True
                    prior_success_id = s3_id if s3_id is not None else default_probe_base_id
        elif c_2 == "QUALIFYING_FAILURE":
            # If S3 was SUCCESS, this loss was already confirmed at S1:
            # (S3=SUCCESS -> S2=FAILURE -> S1=FAILURE). Do not emit on subsequent failures.
            pass

        if confirmed:
            # Describes repeated observed reachability failure while HTTP remains responsive,
            # not definitive proof that the owner intentionally disabled HTTPS.
            error_type = (n_host.get("https") or {}).get("error_type")
            change_dict = {
                "change_type": "HTTPS_LOST",
                "category": "exposure",
                "severity": "MEDIUM",
                "asset": host,
                "detail": "",
                "evidence": "probe",
                "previous_state": {"https_reachable": True},
                "new_state": {"https_reachable": False, "error_type": error_type},
                "observed_at": observed_at,
            }
            if prior_success_id is not None:
                change_dict["baseline_scan_run_id"] = prior_success_id
            changes.append(change_dict)


    # B. Portscan Changes
    # Build portscan history window (up to 3 previous scans, newest to oldest)
    if historical_baselines is not None:
        port_history = [
            entry
            if isinstance(entry, dict) and "reports" in entry
            else {"scan_run_id": None, "reports": entry}
            for entry in historical_baselines[:3]
        ]
    else:
        port_history = [{"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}]

    # Build per-scan host lookup maps once per comparison to avoid repeated full-host searches
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]]]] = []
    for entry in port_history[:3]:
        scan_id = entry.get("scan_run_id") or entry.get("id")
        rep = entry.get("reports") if "reports" in entry else entry
        port_results = (rep.get("portscan") or {}).get("results", [])
        host_map: dict[str, dict[str, Any]] = {}
        if isinstance(port_results, list):
            for r in port_results:
                if isinstance(r, dict) and "subdomain" in r:
                    host_map[r["subdomain"]] = r
        history_indexed.append((scan_id, host_map))

    default_base_id = (
        history_indexed[0][0] if history_indexed else baseline_scan_run_id
    )

    all_port_hosts = set(base_port_hosts.keys()) | set(new_port_hosts.keys())
    for _scan_id, host_map in history_indexed:
        all_port_hosts.update(host_map.keys())

    for host in all_port_hosts:
        n_host_data = new_port_hosts.get(host, {})
        n_probed = str(n_host_data.get("status", "")).upper() == "PROBED"

        n_open_ports_map = {
            p["port"]: p
            for p in n_host_data.get("open_ports", [])
            if p.get("state") == "OPEN" and isinstance(p.get("port"), int)
        }
        n_closed_ports = {
            p
            for p in n_host_data.get("closed_ports", [])
            if isinstance(p, int) and p not in n_open_ports_map
        } if n_probed else set()

        # 1. Port newly open
        for port, p_obj in n_open_ports_map.items():
            latest_def = _find_latest_definite_port_observation(history_indexed, host, port)
            if latest_def is not None and latest_def[0] == "OPEN":
                # Latest definite observation was already OPEN (e.g. OPEN -> FILTERED -> OPEN).
                # Do not emit PORT_NEWLY_OPEN.
                continue

            # Either latest_def was 'CLOSED', or no definite observation exists in bounded history.
            port_finding = next(
                (f for f in new_port_findings.get(host, []) if f.port == port),
                None,
            )
            severity = port_finding.tier if port_finding else "INFO"
            base_id = latest_def[1] if latest_def is not None else default_base_id
            prev_state = {"port": port, "state": "CLOSED"} if latest_def is not None else None

            change_dict: dict[str, Any] = {
                "change_type": "PORT_NEWLY_OPEN",
                "category": "exposure",
                "severity": severity,
                "asset": host,
                "detail": str(port),
                "evidence": "portscan",
                "previous_state": prev_state,
                "new_state": {
                    "port": port,
                    "state": "OPEN",
                    "service": p_obj.get("service_guess"),
                    "banner": p_obj.get("banner"),
                },
                "observed_at": observed_at,
            }
            if base_id is not None:
                change_dict["baseline_scan_run_id"] = base_id
            changes.append(change_dict)

        # 2. Port no longer open
        # ONLY if host was evaluated in new scan (status == 'PROBED')
        if n_probed:
            for port in n_closed_ports:
                latest_def = _find_latest_definite_port_observation(history_indexed, host, port)
                if latest_def is not None and latest_def[0] == "OPEN":
                    # Port was definitely OPEN in history and is now explicitly CLOSED
                    base_id = latest_def[1] if latest_def[1] is not None else default_base_id
                    p_prev = latest_def[2]
                    prev_state = {
                        "port": port,
                        "state": "OPEN",
                    }
                    if p_prev:
                        if p_prev.get("service_guess"):
                            prev_state["service"] = p_prev.get("service_guess")
                        if p_prev.get("banner"):
                            prev_state["banner"] = p_prev.get("banner")

                    change_dict = {
                        "change_type": "PORT_NO_LONGER_OPEN",
                        "category": "exposure",
                        "severity": "INFO",
                        "asset": host,
                        "detail": str(port),
                        "evidence": "portscan",
                        "previous_state": prev_state,
                        "new_state": {"port": port, "state": "CLOSED"},
                        "observed_at": observed_at,
                    }
                    if base_id is not None:
                        change_dict["baseline_scan_run_id"] = base_id
                    changes.append(change_dict)

    # C. Inspect Changes (TLS & Headers)
    # Build inspect history window (up to 3 previous scans, newest to oldest)
    if historical_baselines is not None:
        inspect_history = [
            entry
            if isinstance(entry, dict) and "reports" in entry
            else {"scan_run_id": None, "reports": entry}
            for entry in historical_baselines[:3]
        ]
    else:
        inspect_history = [
            {"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}
        ]

    inspect_history_indexed: list[
        tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]
    ] = []
    for entry in inspect_history:
        scan_id = entry.get("scan_run_id") or entry.get("id")
        rep = entry.get("reports") if "reports" in entry else entry
        insp_results = (rep.get("inspect") or {}).get("results", [])
        host_map: dict[str, dict[str, Any]] = {}
        if isinstance(insp_results, list):
            for r in insp_results:
                if isinstance(r, dict) and "subdomain" in r:
                    host_map[r["subdomain"]] = r
            findings_map = evaluate_inspect_findings(insp_results)
        else:
            findings_map = {}
        inspect_history_indexed.append((scan_id, host_map, findings_map))

    all_inspect_hosts = set(base_insp_hosts.keys()) | set(new_insp_hosts.keys())
    for _scan_id, host_map, _findings in inspect_history_indexed:
        all_inspect_hosts.update(host_map.keys())

    for host in all_inspect_hosts:
        n_host = new_insp_hosts.get(host)
        n_probed = bool(n_host) and str(n_host.get("status", "")).upper() == "PROBED"

        # 1. Certificate Evaluation
        if n_probed and _is_valid_cert_data(n_host.get("cert")):
            n_cert = n_host["cert"]
            n_tls_findings = [
                f for f in new_inspect_findings.get(host, []) if f.id.startswith("TLS_")
            ]
            n_tls_f_keys = {(f.id, _get_inspect_detail(f)): f for f in n_tls_findings}

            cert_base = _find_latest_cert_for_defects(inspect_history_indexed, host)
            if cert_base is not None:
                base_scan_id, _b_host, b_cert, b_tls_findings = cert_base
                b_tls_f_keys = {(f.id, _get_inspect_detail(f)): f for f in b_tls_findings}

                # 1a. New TLS defects (Exposure)
                for key, finding in n_tls_f_keys.items():
                    if key not in b_tls_f_keys:
                        change_type = FINDING_TO_CHANGE_TYPE.get(finding.id)
                        if change_type:
                            change_dict = {
                                "change_type": change_type,
                                "category": "exposure",
                                "severity": finding.tier,
                                "asset": host,
                                "detail": _get_inspect_detail(finding),
                                "evidence": "inspect",
                                "previous_state": None,
                                "new_state": {
                                    "finding_id": finding.id,
                                    "evidence": finding.evidence,
                                },
                                "observed_at": observed_at,
                            }
                            if base_scan_id is not None:
                                change_dict["baseline_scan_run_id"] = base_scan_id
                            changes.append(change_dict)

                # 1b. Resolved TLS defects (Remediation)
                # Requires affirmative evidence that the relevant security check succeeded.
                for key, b_finding in b_tls_f_keys.items():
                    if key not in n_tls_f_keys:
                        if len(n_tls_findings) == 0 and _is_defect_remediated(b_finding.id, n_cert):
                            change_dict = {
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
                            }
                            if base_scan_id is not None:
                                change_dict["baseline_scan_run_id"] = base_scan_id
                            changes.append(change_dict)

                # 1c. Clean Certificate Rotation (Field rule when neither cert had TLS defects)
                # Established policy: if issuer changed, emit issuer; elif not_after changed,
                # emit not_after. Never emits two rotation events for the same host transition.
                if len(b_tls_findings) == 0 and len(n_tls_findings) == 0:
                    clean_base = _find_latest_clean_cert(inspect_history_indexed, host)
                    if clean_base is not None:
                        b_clean_id, _b_h, b_clean_cert = clean_base
                        if (
                            b_clean_cert.get("issuer")
                            and n_cert.get("issuer")
                            and b_clean_cert.get("issuer") != n_cert.get("issuer")
                        ):
                            change_dict = {
                                "change_type": "CERTIFICATE_CHANGED",
                                "category": "exposure",
                                "severity": "INFO",
                                "asset": host,
                                "detail": "issuer",
                                "evidence": "inspect",
                                "previous_state": {"issuer": b_clean_cert.get("issuer")},
                                "new_state": {"issuer": n_cert.get("issuer")},
                                "observed_at": observed_at,
                            }
                            if b_clean_id is not None:
                                change_dict["baseline_scan_run_id"] = b_clean_id
                            changes.append(change_dict)
                        elif (
                            b_clean_cert.get("not_after")
                            and n_cert.get("not_after")
                            and b_clean_cert.get("not_after") != n_cert.get("not_after")
                        ):
                            change_dict = {
                                "change_type": "CERTIFICATE_CHANGED",
                                "category": "exposure",
                                "severity": "INFO",
                                "asset": host,
                                "detail": "not_after",
                                "evidence": "inspect",
                                "previous_state": {"not_after": b_clean_cert.get("not_after")},
                                "new_state": {"not_after": n_cert.get("not_after")},
                                "observed_at": observed_at,
                            }
                            if b_clean_id is not None:
                                change_dict["baseline_scan_run_id"] = b_clean_id
                            changes.append(change_dict)

        # 2. Security Header Evaluation
        if n_probed and _is_valid_header_data(n_host.get("headers")):
            n_headers = n_host["headers"]
            n_header_findings = [
                f for f in new_inspect_findings.get(host, []) if f.id.startswith("HEADER_")
            ]
            n_hdr_f_keys = {(f.id, _get_inspect_detail(f)): f for f in n_header_findings}

            # 2a. Header defects (Exposure: missing headers, weakened HSTS, disclosure)
            for key, finding in n_hdr_f_keys.items():
                if finding.id.startswith("HEADER_MISSING_"):
                    header_name = HEADER_NAME_MAP.get(finding.id) or _get_inspect_detail(finding)
                    hdr_obs = _find_latest_header_observation(
                        inspect_history_indexed, host, header_name
                    )
                    # Only emit REMOVED if prior observation established the header was PRESENT
                    if hdr_obs is not None and hdr_obs[1] == "PRESENT":
                        base_scan_id = hdr_obs[0]
                        change_dict = {
                            "change_type": "SECURITY_HEADER_REMOVED",
                            "category": "exposure",
                            "severity": finding.tier,
                            "asset": host,
                            "detail": header_name,
                            "evidence": "inspect",
                            "previous_state": {"header": header_name, "status": "present"},
                            "new_state": {
                                "finding_id": finding.id,
                                "evidence": finding.evidence,
                            },
                            "observed_at": observed_at,
                        }
                        if base_scan_id is not None:
                            change_dict["baseline_scan_run_id"] = base_scan_id
                        changes.append(change_dict)

                elif finding.id == "HEADER_WEAK_HSTS":
                    hsts_obs = _find_latest_hsts_strength(inspect_history_indexed, host)
                    # Only emit WEAKENED if prior observation established HSTS was STRONG
                    if hsts_obs is not None and hsts_obs[1] == "STRONG":
                        base_scan_id = hsts_obs[0]
                        change_dict = {
                            "change_type": "SECURITY_HEADER_WEAKENED",
                            "category": "exposure",
                            "severity": finding.tier,
                            "asset": host,
                            "detail": "Strict-Transport-Security",
                            "evidence": "inspect",
                            "previous_state": {
                                "header": "Strict-Transport-Security",
                                "status": "strong",
                            },
                            "new_state": {
                                "finding_id": finding.id,
                                "evidence": finding.evidence,
                            },
                            "observed_at": observed_at,
                        }
                        if base_scan_id is not None:
                            change_dict["baseline_scan_run_id"] = base_scan_id
                        changes.append(change_dict)

                else:
                    # General header findings (e.g. HEADER_INFO_DISCLOSURE)
                    header_base = _find_latest_valid_header(inspect_history_indexed, host)
                    if header_base is not None:
                        base_scan_id, _b_host, _b_headers, b_header_findings = header_base
                        b_hdr_f_keys = {
                            (f.id, _get_inspect_detail(f)): f for f in b_header_findings
                        }
                        if key not in b_hdr_f_keys:
                            change_type = FINDING_TO_CHANGE_TYPE.get(finding.id)
                            if change_type:
                                change_dict = {
                                    "change_type": change_type,
                                    "category": "exposure",
                                    "severity": finding.tier,
                                    "asset": host,
                                    "detail": _get_inspect_detail(finding),
                                    "evidence": "inspect",
                                    "previous_state": None,
                                    "new_state": {
                                        "finding_id": finding.id,
                                        "evidence": finding.evidence,
                                    },
                                    "observed_at": observed_at,
                                }
                                if base_scan_id is not None:
                                    change_dict["baseline_scan_run_id"] = base_scan_id
                                changes.append(change_dict)

            # 2b. Remediation: missing header was added
            present_headers = n_headers.get("present_headers")
            if isinstance(present_headers, dict):
                for header_name, h_val in present_headers.items():
                    hdr_obs = _find_latest_header_observation(
                        inspect_history_indexed, host, header_name
                    )
                    # Only emit ADDED if prior observation established the header was MISSING
                    if hdr_obs is not None and hdr_obs[1] == "MISSING":
                        base_scan_id = hdr_obs[0]
                        change_dict = {
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
                                "value": str(h_val),
                            },
                            "observed_at": observed_at,
                        }
                        if base_scan_id is not None:
                            change_dict["baseline_scan_run_id"] = base_scan_id
                        changes.append(change_dict)

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
