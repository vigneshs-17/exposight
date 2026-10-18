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

from asm.models import Finding, HostScore
from asm.scoring import (
    LARGE_ATTACK_SURFACE_THRESHOLD,
    TIER_RANK,
    create_finding,
    derive_domain_band,
    derive_host_band,
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


def classify_discovery_observation(
    sub_name: str,
    scan_source: str,
    scan_truncated: bool,
    scan_empty: bool,
    scan_sub_map: dict[str, dict[str, Any]],
    anchor_source: str,
) -> str:
    """Classify a discovery scan observation for bounded change and inventory tracking.

    Returns:
        'PRESENT': Subdomain was observed present in the scan's discovery results.
        'QUALIFYING_ABSENCE': Subdomain was absent from a non-empty, non-truncated scan
            whose discovery source matched the host's historical anchor source.
        'UNKNOWN': Any absence where the scan was empty (provider outage/failure),
            truncated (pagination/entry limit cap reached), or queried a different provider
            source (incomparable provider switch).
    """
    if sub_name in scan_sub_map:
        return "PRESENT"
    if scan_empty or scan_truncated or (scan_source != anchor_source):
        return "UNKNOWN"
    return "QUALIFYING_ABSENCE"


def _is_valid_cert_data(cert: Any) -> bool:
    """Return True if cert dictionary contains non-empty certificate evidence."""
    return isinstance(cert, dict) and bool(
        cert.get("issuer")
        or cert.get("not_after")
        or cert.get("subject_cn")
        or cert.get("serial_hex")
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
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
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
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
    host: str,
    *,
    issuer: str | None = None,
) -> tuple[int | None, dict[str, Any], dict[str, Any]] | None:
    """Search history window for latest valid certificate observation with no TLS defects.

    When `issuer` is provided, returns the latest clean certificate in the bounded
    history window issued by that same issuer, if one exists.
    """
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
            if issuer is not None and cert.get("issuer") != issuer:
                continue
            return (scan_id, h_data, cert)
    return None


def _certs_are_identical(cert1: dict[str, Any], cert2: dict[str, Any]) -> bool:
    """Return True only if two clean cert dicts represent the same certificate instance.

    Matching issuer name alone is never treated as proof that two certificates are
    identical: both certs must have matching non-empty issuer and not_after values,
    and any additional identity fields present on either certificate (serial_hex,
    not_before, subject_cn, sans) must also match.
    """
    if not (
        cert1.get("issuer")
        and cert2.get("issuer")
        and cert1.get("issuer") == cert2.get("issuer")
        and cert1.get("not_after")
        and cert2.get("not_after")
        and cert1.get("not_after") == cert2.get("not_after")
    ):
        return False
    for field in ("serial_hex", "not_before", "subject_cn"):
        v1 = cert1.get(field)
        v2 = cert2.get(field)
        if (v1 is not None or v2 is not None) and v1 != v2:
            return False
    sans1 = cert1.get("sans")
    sans2 = cert2.get("sans")
    if (sans1 is not None or sans2 is not None) and (
        not isinstance(sans1, list) or not isinstance(sans2, list) or sorted(sans1) != sorted(sans2)
    ):
        return False
    return True


def _find_latest_definite_dns_observation(
    disc_history_indexed: list[tuple[int | None, str, bool, bool, dict[str, dict[str, Any]]]],
    sub: str,
) -> tuple[str, bool, int | None] | None:
    """Search up to 3 historical scans for the latest definite DNS resolution observation.

    Returns:
        (status, resolved, scan_run_id) where status is 'RESOLVED' (resolved=True)
        or 'NXDOMAIN' (resolved=False). Skips TIMEOUT/ERROR and missing entries.
    """
    for s_id, _s_src, _s_trunc, _s_empty, s_subs in disc_history_indexed:
        entry = s_subs.get(sub)
        if not isinstance(entry, dict):
            continue
        stat = entry.get("status")
        res = entry.get("resolved", False) is True
        if stat == "RESOLVED" and res:
            return ("RESOLVED", True, s_id)
        if stat == "NXDOMAIN" and not res:
            return ("NXDOMAIN", False, s_id)
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
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
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
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
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
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
    host: str,
) -> tuple[int | None, dict[str, Any], dict[str, Any], list[Finding]] | None:
    """Search history window for the latest valid certificate observation."""
    return _find_latest_cert_for_defects(history_indexed, host)


def _find_latest_valid_header(
    history_indexed: list[tuple[int | None, dict[str, dict[str, Any]], dict[str, list[Finding]]]],
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


def _tombstone_retention_sort_key(
    sub: str, item: dict[str, Any]
) -> tuple[int, int, float, str, int]:
    """Deterministic retention sort key for removed tombstones (higher values = newer).

    Matches the SQL retention order in ASMWorker._mark_run_final:
    1. removed_at_scan_run_id DESC NULLS LAST
    2. last_applied_scan_run_id DESC NULLS LAST
    3. updated_at DESC NULLS LAST
    4. subdomain DESC (intrinsic tie-breaker independent of DB row-return/insertion order)
    5. id DESC NULLS LAST
    """
    rem_id = item.get("removed_at_scan_run_id")
    app_id = item.get("last_applied_scan_run_id")
    upd = item.get("updated_at")
    if isinstance(upd, datetime):
        upd_ts = (
            upd.timestamp() if upd.tzinfo is not None else upd.replace(tzinfo=UTC).timestamp()
        )
    elif isinstance(upd, (int, float)):
        upd_ts = float(upd)
    else:
        upd_ts = -1.0
    row_id = item.get("id")
    return (
        int(rem_id) if isinstance(rem_id, int) else -1,
        int(app_id) if isinstance(app_id, int) else -1,
        upd_ts,
        sub,
        int(row_id) if isinstance(row_id, int) else -1,
    )


def detect_changes(
    baseline_reports: dict[str, dict[str, Any]],
    new_reports: dict[str, dict[str, Any]],
    *,
    allow_removal: bool = True,
    historical_baselines: list[dict[str, Any]] | None = None,
    baseline_scan_run_id: int | None = None,
    persisted_inventory: dict[str, dict[str, Any]] | None = None,
    persisted_transitions: dict[str, dict[str, Any]] | None = None,
    current_scan_run_id: int | None = None,
    max_active_subdomains: int = 5000,
    max_tombstones: int = 1000,
    is_first_baseline: bool = False,
) -> list[dict[str, Any]]:
    """Pure comparison function to detect attack surface changes between two scans.

    Args:
        baseline_reports: Stage reports of the baseline succeeded scan.
        new_reports: Stage reports of the newly completed scan.
        allow_removal: If False, subdomain deletions will not be emitted.
        historical_baselines: Optional list of up to 3 previous successful scans
            (ordered newest to oldest) with their reports and scan IDs.
        baseline_scan_run_id: Optional ID of the immediate baseline scan run.
        persisted_inventory: Optional mutable inventory map retained across scans.
        persisted_transitions: Optional out-map populated with every inventory row
            created or mutated during this scan before tombstone pruning.

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
        disc_history_entries = [{"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}]
    else:
        disc_history_entries = []

    # Indexed prior scans: list of (scan_id, source, truncated, is_empty, sub_map)
    disc_history_indexed: list[tuple[int | None, str, bool, bool, dict[str, dict[str, Any]]]] = []
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
            classify_discovery_observation(
                sub_name, scan_source, scan_truncated, scan_empty, scan_sub_map, anchor_source
            )
            == "QUALIFYING_ABSENCE"
        )

    if persisted_inventory is not None:
        untracked_subdomains: list[str] = []

        def _record_transition(sub_key: str, entry: dict[str, Any]) -> None:
            if persisted_transitions is not None:
                persisted_transitions[sub_key] = dict(entry)

        # 2a. Additions, Reappearances, and DNS Resolution Transitions
        for sub, n_entry in new_subs.items():
            n_stat = n_entry.get("status")
            n_res = n_entry.get("resolved", False) is True

            if sub not in persisted_inventory:
                active_count = sum(
                    1 for it in persisted_inventory.values() if it.get("status") == "active"
                )
                if is_first_baseline:
                    if active_count < max_active_subdomains:
                        persisted_inventory[sub] = {
                            "subdomain": sub,
                            "status": "active",
                            "anchor_source": new_src,
                            "consecutive_qualifying_absences": 0,
                            "first_seen_scan_run_id": current_scan_run_id,
                            "last_seen_scan_run_id": current_scan_run_id,
                            "last_qualifying_absence_scan_run_id": None,
                            "removed_at_scan_run_id": None,
                            "last_status": n_stat,
                            "last_resolved": n_res,
                            "last_applied_scan_run_id": current_scan_run_id,
                        }
                        _record_transition(sub, persisted_inventory[sub])
                    else:
                        untracked_subdomains.append(sub)
                else:
                    if active_count < max_active_subdomains:
                        persisted_inventory[sub] = {
                            "subdomain": sub,
                            "status": "active",
                            "anchor_source": new_src,
                            "consecutive_qualifying_absences": 0,
                            "first_seen_scan_run_id": current_scan_run_id,
                            "last_seen_scan_run_id": current_scan_run_id,
                            "last_qualifying_absence_scan_run_id": None,
                            "removed_at_scan_run_id": None,
                            "last_status": n_stat,
                            "last_resolved": n_res,
                            "last_applied_scan_run_id": current_scan_run_id,
                        }
                        _record_transition(sub, persisted_inventory[sub])
                        change_dict = {
                            "change_type": "NEW_SUBDOMAIN",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": sub,
                            "detail": "",
                            "evidence": "discover",
                            "previous_state": None,
                            "new_state": {"status": n_stat, "resolved": n_res},
                            "observed_at": observed_at,
                        }
                        if baseline_scan_run_id is not None:
                            change_dict["baseline_scan_run_id"] = baseline_scan_run_id
                        changes.append(change_dict)
                    else:
                        untracked_subdomains.append(sub)
            else:
                item = persisted_inventory[sub]
                if item.get("status") == "removed":
                    # Reappearance after confirmed removal
                    active_count = sum(
                        1 for it in persisted_inventory.values() if it.get("status") == "active"
                    )
                    if active_count < max_active_subdomains:
                        item["status"] = "active"
                        item["anchor_source"] = new_src
                        item["consecutive_qualifying_absences"] = 0
                        item["last_seen_scan_run_id"] = current_scan_run_id
                        item["last_status"] = n_stat
                        item["last_resolved"] = n_res
                        item["removed_at_scan_run_id"] = None
                        item["last_applied_scan_run_id"] = current_scan_run_id
                        _record_transition(sub, item)
                        change_dict = {
                            "change_type": "NEW_SUBDOMAIN",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": sub,
                            "detail": "",
                            "evidence": "discover",
                            "previous_state": None,
                            "new_state": {"status": n_stat, "resolved": n_res},
                            "observed_at": observed_at,
                        }
                        if baseline_scan_run_id is not None:
                            change_dict["baseline_scan_run_id"] = baseline_scan_run_id
                        changes.append(change_dict)
                    else:
                        untracked_subdomains.append(sub)
                else:
                    # Active host presence
                    b_stat = item.get("last_status")
                    b_res = item.get("last_resolved")
                    b_id = item.get("last_seen_scan_run_id") or baseline_scan_run_id

                    item["consecutive_qualifying_absences"] = 0
                    item["last_seen_scan_run_id"] = current_scan_run_id
                    if not new_trunc:
                        item["anchor_source"] = new_src
                    item["last_status"] = n_stat
                    item["last_resolved"] = n_res
                    item["last_applied_scan_run_id"] = current_scan_run_id
                    _record_transition(sub, item)

                    if b_stat == "NXDOMAIN" and n_stat == "RESOLVED" and n_res:
                        change_dict = {
                            "change_type": "NEWLY_RESOLVING",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": sub,
                            "detail": "",
                            "evidence": "discover",
                            "previous_state": {"status": b_stat, "resolved": b_res},
                            "new_state": {"status": n_stat, "resolved": n_res},
                            "observed_at": observed_at,
                        }
                        if b_id is not None:
                            change_dict["baseline_scan_run_id"] = b_id
                        changes.append(change_dict)
                    elif b_stat == "RESOLVED" and b_res and n_stat == "NXDOMAIN" and not n_res:
                        change_dict = {
                            "change_type": "STOPPED_RESOLVING",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": sub,
                            "detail": "",
                            "evidence": "discover",
                            "previous_state": {"status": b_stat, "resolved": b_res},
                            "new_state": {"status": n_stat, "resolved": n_res},
                            "observed_at": observed_at,
                        }
                        if b_id is not None:
                            change_dict["baseline_scan_run_id"] = b_id
                        changes.append(change_dict)

        if (
            untracked_subdomains
            and "discover" in new_reports
            and isinstance(new_reports["discover"], dict)
        ):
            new_reports["discover"]["truncated"] = True
            new_reports["discover"]["truncation_reason"] = "inventory_capacity_exceeded"
            new_reports["discover"]["untracked_subdomains_count"] = len(untracked_subdomains)

        # 2b. Removals (iterate in deterministic subdomain order independent of DB row order)
        if not is_first_baseline:
            for sub in sorted(persisted_inventory.keys()):
                item = persisted_inventory[sub]
                if item.get("status") != "active":
                    continue
                if sub in new_subs:
                    continue

                anchor_src = item.get("anchor_source", "crt.sh")
                obs = classify_discovery_observation(
                    sub, new_src, new_trunc, new_empty, new_subs, anchor_src
                )
                if obs != "QUALIFYING_ABSENCE":
                    # An unknown observation (provider switch, truncated scan, or empty scan)
                    # retains the host's presence anchor but breaks the consecutive absence streak.
                    if item.get("consecutive_qualifying_absences", 0) != 0:
                        item["consecutive_qualifying_absences"] = 0
                        _record_transition(sub, item)
                    continue

                if allow_removal:
                    item["last_applied_scan_run_id"] = current_scan_run_id
                    if item.get("last_qualifying_absence_scan_run_id") != current_scan_run_id:
                        item["consecutive_qualifying_absences"] = (
                            item.get("consecutive_qualifying_absences", 0) + 1
                        )
                        item["last_qualifying_absence_scan_run_id"] = current_scan_run_id

                    if item["consecutive_qualifying_absences"] == 2:
                        item["status"] = "removed"
                        item["removed_at_scan_run_id"] = current_scan_run_id
                        base_id = item.get("last_seen_scan_run_id") or baseline_scan_run_id
                        change_dict = {
                            "change_type": "REMOVED_SUBDOMAIN",
                            "category": "exposure",
                            "severity": "INFO",
                            "asset": sub,
                            "detail": "",
                            "evidence": "discover",
                            "previous_state": {
                                "status": item.get("last_status"),
                                "resolved": item.get("last_resolved"),
                            },
                            "new_state": None,
                            "observed_at": observed_at,
                        }
                        if base_id is not None:
                            change_dict["baseline_scan_run_id"] = base_id
                        changes.append(change_dict)

                    _record_transition(sub, item)

        # 2c. Tombstone pruning (retain newest max_tombstones deterministically)
        tombstones = [k for k, v in persisted_inventory.items() if v.get("status") == "removed"]
        if len(tombstones) > max_tombstones:
            tombstones_newest_first = sorted(
                tombstones,
                key=lambda k: _tombstone_retention_sort_key(k, persisted_inventory[k]),
                reverse=True,
            )
            for k in tombstones_newest_first[max_tombstones:]:
                del persisted_inventory[k]
    else:
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
                changes.append(
                    {
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
                    }
                )
            else:
                # Case 2: Present in history.
                # Did it undergo confirmed absence immediately before new scan?
                pres_idx, _p_id, anchor_src, _p_entry = last_present
                s1_qualifies = len(disc_history_indexed) >= 1 and _is_qualifying_absence(
                    sub,
                    disc_history_indexed[0][1],
                    disc_history_indexed[0][2],
                    disc_history_indexed[0][3],
                    disc_history_indexed[0][4],
                    anchor_src,
                )
                s2_qualifies = len(disc_history_indexed) >= 2 and _is_qualifying_absence(
                    sub,
                    disc_history_indexed[1][1],
                    disc_history_indexed[1][2],
                    disc_history_indexed[1][3],
                    disc_history_indexed[1][4],
                    anchor_src,
                )

                if s1_qualifies and s2_qualifies and pres_idx >= 2:
                    # Confirmed absent prior to new scan -> Genuine rediscovery
                    s1_id = disc_history_indexed[0][0] or default_base_id
                    changes.append(
                        {
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
                        }
                    )
                else:
                    # Case 3: Noise recovery or stable presence -> evaluate DNS
                    # resolution transitions against the latest definite DNS observation
                    # in the bounded history window.
                    latest_dns = _find_latest_definite_dns_observation(disc_history_indexed, sub)
                    if latest_dns is not None:
                        b_stat, b_res, b_dns_id = latest_dns
                        n_stat = n_entry.get("status")
                        n_res = n_entry.get("resolved", False) is True

                        # NXDOMAIN -> RESOLVED
                        if b_stat == "NXDOMAIN" and n_stat == "RESOLVED" and n_res:
                            change_dict: dict[str, Any] = {
                                "change_type": "NEWLY_RESOLVING",
                                "category": "exposure",
                                "severity": "INFO",
                                "asset": sub,
                                "detail": "",
                                "evidence": "discover",
                                "previous_state": {"status": b_stat, "resolved": b_res},
                                "new_state": {"status": n_stat, "resolved": n_res},
                                "observed_at": observed_at,
                            }
                            if b_dns_id is not None:
                                change_dict["baseline_scan_run_id"] = b_dns_id
                            changes.append(change_dict)
                        # RESOLVED -> NXDOMAIN (Definite stop; TIMEOUT / ERROR are ignored)
                        elif b_stat == "RESOLVED" and b_res and n_stat == "NXDOMAIN" and not n_res:
                            change_dict = {
                                "change_type": "STOPPED_RESOLVING",
                                "category": "exposure",
                                "severity": "INFO",
                                "asset": sub,
                                "detail": "",
                                "evidence": "discover",
                                "previous_state": {"status": b_stat, "resolved": b_res},
                                "new_state": {"status": n_stat, "resolved": n_res},
                                "observed_at": observed_at,
                            }
                            if b_dns_id is not None:
                                change_dict["baseline_scan_run_id"] = b_dns_id
                            changes.append(change_dict)

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
        probe_history_entries = [{"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}]
    else:
        probe_history_entries = []

    probe_history_indexed: list[tuple[int | None, dict[str, dict[str, Any]]]] = []
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

    default_base_id = history_indexed[0][0] if history_indexed else baseline_scan_run_id

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
        n_closed_ports = (
            {
                p
                for p in n_host_data.get("closed_ports", [])
                if isinstance(p, int) and p not in n_open_ports_map
            }
            if n_probed
            else set()
        )

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
        inspect_history = [{"scan_run_id": baseline_scan_run_id, "reports": baseline_reports}]

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
                # Same-issuer lookback within the 3-scan window detects not_after rotation across
                # an intervening alternate edge cert (A_old -> B -> A_rotated) and suppresses
                # return-leg issuer events only when returning to the exact same certificate
                # instance (A -> B -> A verified by _certs_are_identical).
                if len(b_tls_findings) == 0 and len(n_tls_findings) == 0:
                    n_issuer = n_cert.get("issuer")
                    same_issuer_base = (
                        _find_latest_clean_cert(inspect_history_indexed, host, issuer=n_issuer)
                        if n_issuer
                        else None
                    )
                    handled_by_same_issuer = False
                    if same_issuer_base is not None:
                        b_same_id, _b_h, b_same_cert = same_issuer_base
                        if (
                            b_same_cert.get("not_after")
                            and n_cert.get("not_after")
                            and b_same_cert.get("not_after") != n_cert.get("not_after")
                        ):
                            change_dict = {
                                "change_type": "CERTIFICATE_CHANGED",
                                "category": "exposure",
                                "severity": "INFO",
                                "asset": host,
                                "detail": "not_after",
                                "evidence": "inspect",
                                "previous_state": {"not_after": b_same_cert.get("not_after")},
                                "new_state": {"not_after": n_cert.get("not_after")},
                                "observed_at": observed_at,
                            }
                            if b_same_id is not None:
                                change_dict["baseline_scan_run_id"] = b_same_id
                            changes.append(change_dict)
                            handled_by_same_issuer = True
                        elif _certs_are_identical(b_same_cert, n_cert):
                            handled_by_same_issuer = True

                    if not handled_by_same_issuer:
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
    # Note on reconstructed vs. persisted ScoreReport values:
    # Persisted ScoreReport (`new_reports["score"]`) always records the raw point-in-time
    # findings of a scan run. Section 4 computes stabilized comparison postures so that
    # single-scan stage incompleteness (unresolved discovery glitches, filtered scored ports,
    # unconfirmed 1-scan HTTP_NO_HTTPS probe failures, or partial TLS/header inspection
    # timeouts) does not trigger false HOST_RISK_BAND_* or DOMAIN_RISK_BAND_* transitions,
    # while preserving fresh defects and canonical scoring rules (`derive_host_band`,
    # `derive_domain_band`, and `LARGE_ATTACK_SURFACE`).
    base_score = baseline_reports.get("score") or {}
    new_score = new_reports.get("score") or {}
    domain_name = new_disc.get("domain") or new_score.get("domain", "")

    # Build bounded scan sequence [S0 (new), S1, S2, S3] and pre-index all stage observations
    score_scans: list[tuple[int | None, dict[str, Any]]] = [(None, new_reports)]
    for entry in disc_history_entries:
        s_id = entry.get("scan_run_id") or entry.get("id")
        rep = entry.get("reports") if "reports" in entry else entry
        score_scans.append((s_id, rep))

    has_stage_reports_by_scan: list[bool] = []
    raw_score_hosts_by_scan: list[dict[str, dict[str, Any]]] = []
    disc_by_scan: list[dict[str, dict[str, Any]] | None] = []
    disc_meta_by_scan: list[tuple[str, bool, bool, dict[str, dict[str, Any]]]] = []
    probe_by_scan: list[dict[str, dict[str, Any]] | None] = []
    portscan_by_scan: list[dict[str, dict[str, Any]] | None] = []
    inspect_by_scan: list[dict[str, dict[str, Any]] | None] = []
    probe_findings_by_scan: list[dict[str, list[Finding]]] = []
    portscan_findings_by_scan: list[dict[str, list[Finding]]] = []
    inspect_findings_by_scan: list[dict[str, list[Finding]]] = []
    scored_port_findings: dict[tuple[int, str, int], Finding] = {}
    ever_scored_ports: dict[str, set[int]] = {}

    for s_idx, (_s_id, rep) in enumerate(score_scans):
        has_stage_reports_by_scan.append(
            any(k in rep for k in ("discover", "probe", "portscan", "inspect"))
        )
        raw_score_hosts_by_scan.append(
            {
                h["subdomain"]: h
                for h in (rep.get("score") or {}).get("hosts", [])
                if isinstance(h, dict) and "subdomain" in h
            }
        )

        d_rep = rep.get("discover") or {}
        d_src = str(d_rep.get("source", "crt.sh"))
        d_trunc = bool(d_rep.get("truncated", False))
        d_res = d_rep.get("results")
        d_subs = (
            {r["subdomain"]: r for r in d_res if isinstance(r, dict) and "subdomain" in r}
            if isinstance(d_res, list)
            else {}
        )
        d_empty = len(d_subs) == 0
        disc_meta_by_scan.append((d_src, d_trunc, d_empty, d_subs))
        disc_by_scan.append(d_subs if d_subs else None)

        pr_res = (rep.get("probe") or {}).get("results")
        if isinstance(pr_res, list) and len(pr_res) > 0:
            probe_by_scan.append(
                {r["subdomain"]: r for r in pr_res if isinstance(r, dict) and "subdomain" in r}
            )
            probe_findings_by_scan.append(evaluate_probe_findings(pr_res))
        else:
            probe_by_scan.append(None)
            probe_findings_by_scan.append({})

        ps_res = (rep.get("portscan") or {}).get("results")
        if isinstance(ps_res, list) and len(ps_res) > 0:
            portscan_by_scan.append(
                {r["subdomain"]: r for r in ps_res if isinstance(r, dict) and "subdomain" in r}
            )
            ps_f_map = evaluate_portscan_findings(ps_res)
            portscan_findings_by_scan.append(ps_f_map)
            for h_name, f_list in ps_f_map.items():
                for f in f_list:
                    if isinstance(f.port, int):
                        scored_port_findings[(s_idx, h_name, f.port)] = f
                        ever_scored_ports.setdefault(h_name, set()).add(f.port)
        else:
            portscan_by_scan.append(None)
            portscan_findings_by_scan.append({})

        in_res = (rep.get("inspect") or {}).get("results")
        if isinstance(in_res, list) and len(in_res) > 0:
            inspect_by_scan.append(
                {r["subdomain"]: r for r in in_res if isinstance(r, dict) and "subdomain" in r}
            )
            inspect_findings_by_scan.append(evaluate_inspect_findings(in_res))
        else:
            inspect_by_scan.append(None)
            inspect_findings_by_scan.append({})

    effective_host_cache: dict[tuple[int, str], dict[str, Any] | None] = {}

    def _effective_host_score(scan_idx: int, host: str) -> dict[str, Any] | None:
        """Return a host score dict backed by confirmed stage findings, or None if unresolved."""
        cache_key = (scan_idx, host)
        if cache_key in effective_host_cache:
            return effective_host_cache[cache_key]

        raw_host_score = raw_score_hosts_by_scan[scan_idx].get(host)
        if not has_stage_reports_by_scan[scan_idx]:
            effective_host_cache[cache_key] = raw_host_score
            return raw_host_score

        # 1. Discovery: unresolved or absent hosts were not scanned in downstream stages
        d_map = disc_by_scan[scan_idx]
        if d_map is not None:
            d_entry = d_map.get(host)
            if d_entry is None:
                effective_host_cache[cache_key] = None
                return None
            if d_entry.get("resolved") is not True or d_entry.get("status") in (
                "TIMEOUT",
                "ERROR",
                "NXDOMAIN",
            ):
                effective_host_cache[cache_key] = None
                return None

        # 2. Portscan: evaluate fresh open ports; filtered scored ports or unprobed
        # portscan fall back
        ps_map = portscan_by_scan[scan_idx]
        ps_entry = ps_map.get(host) if ps_map is not None else None
        ps_probed = ps_entry is not None and str(ps_entry.get("status", "")).upper() == "PROBED"
        filtered_scored_ports: list[int] = []
        if ps_probed:
            filt = ps_entry.get("filtered_ports") or []
            if isinstance(filt, list):
                filtered_scored_ports = [
                    p
                    for p in filt
                    if isinstance(p, int) and p in ever_scored_ports.get(host, set())
                ]

        # 3. Inspect: evaluate certificate and header sub-observations independently
        in_map = inspect_by_scan[scan_idx]
        in_entry = in_map.get(host) if in_map is not None else None
        in_probed = in_entry is not None and str(in_entry.get("status", "")).upper() == "PROBED"
        cert_valid_now = in_probed and _is_valid_cert_data(in_entry.get("cert"))
        hdr_valid_now = in_probed and _is_valid_header_data(in_entry.get("headers"))

        # 4. Probe: check for unconfirmed 1-scan QUALIFYING_FAILURE (HTTP_NO_HTTPS)
        pr_map = probe_by_scan[scan_idx]
        pr_entry = pr_map.get(host) if pr_map is not None else None
        unconfirmed_probe_fail = False
        if (
            pr_map is not None
            and _classify_https_probe_observation(pr_entry) == "QUALIFYING_FAILURE"
        ):
            confirmed_fail = False
            if scan_idx + 1 < len(score_scans):
                prev_pr_map = probe_by_scan[scan_idx + 1]
                prev_pr = prev_pr_map.get(host) if prev_pr_map is not None else None
                if _classify_https_probe_observation(prev_pr) == "QUALIFYING_FAILURE":
                    confirmed_fail = True
            if not confirmed_fail:
                raw_f_list = (raw_host_score or {}).get("findings") or []
                has_http_no_https_in_raw = any(
                    isinstance(f, dict) and f.get("id") == "HTTP_NO_HTTPS" for f in raw_f_list
                )
                if has_http_no_https_in_raw or not (cert_valid_now and hdr_valid_now):
                    unconfirmed_probe_fail = True

        cert_needs_fallback = (
            in_map is not None and not cert_valid_now and (in_probed or unconfirmed_probe_fail)
        )
        hdr_needs_fallback = (
            in_map is not None and not hdr_valid_now and (in_probed or unconfirmed_probe_fail)
        )
        ps_needs_fallback = not ps_probed or bool(filtered_scored_ports)

        if (
            not ps_needs_fallback
            and not unconfirmed_probe_fail
            and not cert_needs_fallback
            and not hdr_needs_fallback
        ):
            effective_host_cache[cache_key] = raw_host_score
            return raw_host_score

        # Reconstruct stabilized host score by combining fresh stage observations with
        # per-substage fallback for only the incomplete/unconfirmed observation(s).
        combined_findings: list[Finding] = []

        # Probe findings
        if pr_map is not None and pr_entry is not None and not unconfirmed_probe_fail:
            combined_findings.extend(probe_findings_by_scan[scan_idx].get(host, []))

        # Portscan findings (fresh open ports + per-port fallback for filtered scored ports,
        # or stage fallback if portscan is unprobed so unknown observations are not treated
        # as remediation)
        if ps_probed:
            ps_findings = list(portscan_findings_by_scan[scan_idx].get(host, []))
            present_ports = {f.port for f in ps_findings if isinstance(f.port, int)}
            for p in filtered_scored_ports:
                if p in present_ports:
                    continue
                for older_idx in range(scan_idx + 1, len(score_scans)):
                    older_ps_map = portscan_by_scan[older_idx]
                    older_ps = older_ps_map.get(host) if older_ps_map is not None else None
                    if older_ps is None or str(older_ps.get("status", "")).upper() != "PROBED":
                        continue
                    open_p = {
                        op.get("port")
                        for op in (older_ps.get("open_ports") or [])
                        if isinstance(op, dict) and op.get("state") == "OPEN"
                    }
                    closed_p = set(older_ps.get("closed_ports") or [])
                    if p in open_p:
                        older_f = scored_port_findings.get((older_idx, host, p))
                        if older_f is not None:
                            ps_findings.append(older_f)
                        break
                    if p in closed_p:
                        break
            combined_findings.extend(ps_findings)
        else:
            # Unprobed/unavailable portscan: fall back to latest valid prior portscan observation
            for older_idx in range(scan_idx + 1, len(score_scans)):
                older_ps_map = portscan_by_scan[older_idx]
                older_ps = older_ps_map.get(host) if older_ps_map is not None else None
                if older_ps is not None and str(older_ps.get("status", "")).upper() == "PROBED":
                    combined_findings.extend(portscan_findings_by_scan[older_idx].get(host, []))
                    break

        # Inspect findings: certificate (TLS_*) and headers (HEADER_*) separated
        if in_map is not None:
            if cert_valid_now:
                combined_findings.extend(
                    f
                    for f in inspect_findings_by_scan[scan_idx].get(host, [])
                    if f.id.startswith("TLS_")
                )
            elif cert_needs_fallback:
                for older_idx in range(scan_idx + 1, len(score_scans)):
                    older_in_map = inspect_by_scan[older_idx]
                    older_in = older_in_map.get(host) if older_in_map is not None else None
                    if (
                        older_in is not None
                        and str(older_in.get("status", "")).upper() == "PROBED"
                        and _is_valid_cert_data(older_in.get("cert"))
                    ):
                        combined_findings.extend(
                            f
                            for f in inspect_findings_by_scan[older_idx].get(host, [])
                            if f.id.startswith("TLS_")
                        )
                        break

            if hdr_valid_now:
                combined_findings.extend(
                    f
                    for f in inspect_findings_by_scan[scan_idx].get(host, [])
                    if f.id.startswith("HEADER_")
                )
            elif hdr_needs_fallback:
                for older_idx in range(scan_idx + 1, len(score_scans)):
                    older_in_map = inspect_by_scan[older_idx]
                    older_in = older_in_map.get(host) if older_in_map is not None else None
                    if (
                        older_in is not None
                        and str(older_in.get("status", "")).upper() == "PROBED"
                        and _is_valid_header_data(older_in.get("headers"))
                    ):
                        combined_findings.extend(
                            f
                            for f in inspect_findings_by_scan[older_idx].get(host, [])
                            if f.id.startswith("HEADER_")
                        )
                        break

        band = derive_host_band(combined_findings)
        score_val = sum(f.points for f in combined_findings)
        reconstructed = {
            "subdomain": host,
            "band": band,
            "score": score_val,
            "findings": [f.to_dict() for f in combined_findings],
            "reconstructed": True,
        }
        effective_host_cache[cache_key] = reconstructed
        return reconstructed

    new_hosts = raw_score_hosts_by_scan[0]

    for host in new_hosts:
        n_host_score = _effective_host_score(0, host)
        if n_host_score is None:
            continue

        b_host_score = None
        b_score_scan_id: int | None = None
        for idx in range(1, len(score_scans)):
            s_id, _rep = score_scans[idx]
            if host in raw_score_hosts_by_scan[idx]:
                eff_b = _effective_host_score(idx, host)
                if eff_b is not None:
                    b_host_score = eff_b
                    b_score_scan_id = s_id
                    break

        if b_host_score is not None:
            b_band = b_host_score.get("band", "INFO")
            n_band = n_host_score.get("band", "INFO")
            b_rank = TIER_RANK.get(b_band, 0)
            n_rank = TIER_RANK.get(n_band, 0)

            if n_rank > b_rank:
                change_dict = {
                    "change_type": "HOST_RISK_BAND_INCREASED",
                    "category": "summary",
                    "severity": n_band,
                    "asset": host,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {"band": b_band, "score": b_host_score.get("score")},
                    "new_state": {"band": n_band, "score": n_host_score.get("score")},
                    "observed_at": observed_at,
                }
                if b_score_scan_id is not None:
                    change_dict["baseline_scan_run_id"] = b_score_scan_id
                changes.append(change_dict)
            elif n_rank < b_rank:
                change_dict = {
                    "change_type": "HOST_RISK_BAND_DECREASED",
                    "category": "summary",
                    "severity": "INFO",
                    "asset": host,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {"band": b_band, "score": b_host_score.get("score")},
                    "new_state": {"band": n_band, "score": n_host_score.get("score")},
                    "observed_at": observed_at,
                }
                if b_score_scan_id is not None:
                    change_dict["baseline_scan_run_id"] = b_score_scan_id
                changes.append(change_dict)

    # Domain risk band (reusing canonical derive_domain_band and domain_findings semantics)
    removed_assets = {c["asset"] for c in changes if c["change_type"] == "REMOVED_SUBDOMAIN"}

    def _effective_domain_band_and_score(target_idx: int) -> tuple[str | None, Any, bool]:
        rep = score_scans[target_idx][1]
        sc = rep.get("score") or {}
        curr_map = raw_score_hosts_by_scan[target_idx]
        if not has_stage_reports_by_scan[target_idx]:
            raw_esc = bool((sc.get("counts") or {}).get("high_escalation"))
            return sc.get("domain_band"), sc.get("domain_score"), raw_esc

        candidate_hosts = set(curr_map.keys())
        # Inspect older scans within the history window (target_idx + 1 .. len(score_scans) - 1)
        # to determine which historical hosts should be retained in domain inventory.
        # A historical host is retained unless it underwent confirmed removal (2 consecutive
        # qualifying absences under discovery observation-validity rules) before or at target_idx.
        for idx in range(target_idx + 1, len(score_scans)):
            for h_name in raw_score_hosts_by_scan[idx]:
                if h_name in candidate_hosts:
                    continue
                if target_idx == 0 and h_name in removed_assets:
                    continue

                # Find the most recent historical scan where h_name was PRESENT
                # (which is the earliest p_idx in target_idx + 1 .. len(score_scans) - 1)
                pres_idx = None
                for p_idx in range(target_idx + 1, len(score_scans)):
                    if h_name in disc_meta_by_scan[p_idx][3]:
                        pres_idx = p_idx
                        break
                if pres_idx is None:
                    pres_idx = idx

                anchor_src = disc_meta_by_scan[pres_idx][0]

                # Check intervening scans from pres_idx - 1 down to target_idx
                # (in chronological order) for 2 consecutive qualifying absences
                consecutive_qa = 0
                confirmed_removed = False
                for k in range(pres_idx - 1, target_idx - 1, -1):
                    k_src, k_trunc, k_empty, k_subs = disc_meta_by_scan[k]
                    obs = classify_discovery_observation(
                        h_name, k_src, k_trunc, k_empty, k_subs, anchor_src
                    )
                    if obs == "PRESENT":
                        consecutive_qa = 0
                    elif obs == "QUALIFYING_ABSENCE":
                        consecutive_qa += 1
                        if consecutive_qa >= 2:
                            confirmed_removed = True
                            break
                    else:
                        # UNKNOWN (truncated, empty, provider switch) resets QA streak
                        consecutive_qa = 0

                if not confirmed_removed:
                    candidate_hosts.add(h_name)

        effective_hosts: dict[str, dict[str, Any]] = {}
        any_substituted = False
        for h_name in candidate_hosts:
            eff_curr = _effective_host_score(target_idx, h_name) if h_name in curr_map else None
            if eff_curr is not None:
                effective_hosts[h_name] = eff_curr
                if eff_curr is not curr_map.get(h_name):
                    any_substituted = True
            else:
                substituted = None
                for idx in range(target_idx + 1, len(score_scans)):
                    if h_name in raw_score_hosts_by_scan[idx]:
                        eff_older = _effective_host_score(idx, h_name)
                        if eff_older is not None:
                            substituted = eff_older
                            break
                if substituted is not None:
                    effective_hosts[h_name] = substituted
                    any_substituted = True
                elif h_name in curr_map:
                    effective_hosts[h_name] = curr_map[h_name]
                else:
                    for idx in range(target_idx + 1, len(score_scans)):
                        if h_name in raw_score_hosts_by_scan[idx]:
                            effective_hosts[h_name] = raw_score_hosts_by_scan[idx][h_name]
                            any_substituted = True
                            break

        host_score_objs = [
            HostScore(
                subdomain=h_name,
                score=int(h_obj.get("score", 0) or 0),
                band=str(h_obj.get("band", "INFO")),
            )
            for h_name, h_obj in sorted(effective_hosts.items())
        ]
        canonical_band, is_escalated = derive_domain_band(host_score_objs)

        if not any_substituted:
            return sc.get("domain_band") or canonical_band, sc.get("domain_score"), is_escalated

        # Preserve existing non-scale domain findings and evaluate LARGE_ATTACK_SURFACE
        # consistently against the stabilized host inventory.
        raw_dom_findings = [
            f
            for f in (sc.get("domain_findings") or [])
            if isinstance(f, dict) and f.get("id") != "LARGE_ATTACK_SURFACE"
        ]
        dom_pts = sum(int(f.get("points", 0) or 0) for f in raw_dom_findings)
        if len(effective_hosts) >= LARGE_ATTACK_SURFACE_THRESHOLD:
            las_f = create_finding(
                "LARGE_ATTACK_SURFACE",
                domain_name or sc.get("domain", ""),
                "discover",
                f"Domain has {len(effective_hosts)} discovered host assets.",
            )
            dom_pts += las_f.points

        eff_score = sum(h.score for h in host_score_objs) + dom_pts
        return canonical_band, eff_score, is_escalated

    if len(score_scans) >= 2:
        b_domain_band, b_domain_score, _b_esc = _effective_domain_band_and_score(1)
        n_domain_band, n_domain_score, _n_esc = _effective_domain_band_and_score(0)
    else:
        b_domain_band = base_score.get("domain_band")
        b_domain_score = base_score.get("domain_score")
        n_domain_band = new_score.get("domain_band")
        n_domain_score = new_score.get("domain_score")

    if b_domain_band and n_domain_band and domain_name:
        b_d_rank = TIER_RANK.get(b_domain_band, 0)
        n_d_rank = TIER_RANK.get(n_domain_band, 0)

        if n_d_rank > b_d_rank:
            changes.append(
                {
                    "change_type": "DOMAIN_RISK_BAND_INCREASED",
                    "category": "summary",
                    "severity": n_domain_band,
                    "asset": domain_name,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {
                        "band": b_domain_band,
                        "score": b_domain_score,
                    },
                    "new_state": {
                        "band": n_domain_band,
                        "score": n_domain_score,
                    },
                    "observed_at": observed_at,
                }
            )
        elif n_d_rank < b_d_rank:
            changes.append(
                {
                    "change_type": "DOMAIN_RISK_BAND_DECREASED",
                    "category": "summary",
                    "severity": "INFO",
                    "asset": domain_name,
                    "detail": "",
                    "evidence": "score",
                    "previous_state": {
                        "band": b_domain_band,
                        "score": b_domain_score,
                    },
                    "new_state": {
                        "band": n_domain_band,
                        "score": n_domain_score,
                    },
                    "observed_at": observed_at,
                }
            )

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
