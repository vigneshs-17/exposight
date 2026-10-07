"""UI view models, data extractors, and pure presentation logic for Exposight dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

TIER_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

TIER_DISPLAY_NAMES: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}

STATUS_DISPLAY_NAMES: dict[str, str] = {
    "queued": "Queued",
    "running": "Running",
    "succeeded": "Succeeded",
    "failed": "Failed",
}


@dataclass(frozen=True)
class FormattedFinding:
    """Sanitized finding item ready for safe template rendering."""

    id: str
    title: str
    tier: str
    tier_display: str
    points: int
    host: str
    port: int | None
    evidence: str
    why_it_matters: str


@dataclass(frozen=True)
class FixFirstResult:
    """Prioritized findings result with metadata and overflow counts."""

    findings: list[FormattedFinding]
    total: int
    more_count: int
    domain_score: int
    domain_band: str
    domain_band_display: str
    counts: dict[str, int]


def _finding_sort_key(f: FormattedFinding) -> tuple[int, int, str, tuple[int, int]]:
    tier_rank = TIER_ORDER.get(f.tier.upper(), 99)
    port_key = (0, 0) if f.port is None else (1, f.port)
    return (tier_rank, -f.points, f.host.lower(), port_key)


def extract_fix_first_findings(score_report: dict[str, Any] | None) -> FixFirstResult:
    """Extract, sort, and cap findings from a raw score stage report.

    Sorting Precedence:
        1. Severity Tier: CRITICAL > HIGH > MEDIUM > LOW > INFO (unknown tiers sort last)
        2. Points: Descending
        3. Host: Ascending (case-insensitive)
        4. Port: Ascending (None precedes numeric ports)

    Defensive Rules:
        - Accepts None or malformed non-dict input gracefully, returning empty FixFirstResult.
        - Caps findings at 50; calculates more_count = max(0, total - 50).
        - Sanitizes missing or non-string/non-int fields with safe defaults.

    Counts:
        Per-tier counts (CRITICAL, HIGH, MEDIUM, LOW, INFO) are computed from ALL parsed
        findings before the 50 cap. The report's own "counts" field is not read: its keys
        (findings_critical, hosts_high, ...) are a scoring.py internal, so the summary
        cards stay consistent with the findings table instead.
    """
    if not isinstance(score_report, dict):
        return FixFirstResult(
            findings=[],
            total=0,
            more_count=0,
            domain_score=0,
            domain_band="UNKNOWN",
            domain_band_display="Unknown",
            counts=dict.fromkeys(TIER_ORDER, 0),
        )

    domain_score = score_report.get("domain_score", 0)
    try:
        domain_score = int(domain_score)
    except (ValueError, TypeError):
        domain_score = 0

    raw_band = str(score_report.get("domain_band", "UNKNOWN")).upper()
    band_display = TIER_DISPLAY_NAMES.get(raw_band, raw_band.capitalize())

    all_findings: list[FormattedFinding] = []
    hosts = score_report.get("hosts", [])
    groups: list[dict[str, Any]] = (
        [h for h in hosts if isinstance(h, dict)] if isinstance(hosts, list) else []
    )
    # Domain-wide findings (v3.6c+); older reports have no such key and are unaffected.
    groups.append(
        {
            "subdomain": score_report.get("domain") or "",
            "findings": score_report.get("domain_findings") or [],
        }
    )
    for host_entry in groups:
        default_host = str(host_entry.get("subdomain") or host_entry.get("host") or "")
        findings_list = host_entry.get("findings", [])
        if not isinstance(findings_list, list):
            continue
        for item in findings_list:
            if not isinstance(item, dict):
                continue
            raw_tier = str(item.get("tier", "INFO")).upper()
            tier_display = TIER_DISPLAY_NAMES.get(raw_tier, raw_tier.capitalize())
            raw_points = item.get("points", 0)
            try:
                points = int(raw_points)
            except (ValueError, TypeError):
                points = 0

            host = str(item.get("host") or default_host)
            port = item.get("port")
            if port is not None:
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    port = None

            all_findings.append(
                FormattedFinding(
                    id=str(item.get("id", "")),
                    title=str(item.get("title", "")),
                    tier=raw_tier,
                    tier_display=tier_display,
                    points=points,
                    host=host,
                    port=port,
                    evidence=str(item.get("evidence", "")),
                    why_it_matters=str(item.get("why_it_matters", "")),
                )
            )

    counts = dict.fromkeys(TIER_ORDER, 0)
    for finding in all_findings:
        if finding.tier in counts:
            counts[finding.tier] += 1

    all_findings.sort(key=_finding_sort_key)
    total = len(all_findings)
    capped_findings = all_findings[:50]
    more_count = max(0, total - 50)

    return FixFirstResult(
        findings=capped_findings,
        total=total,
        more_count=more_count,
        domain_score=domain_score,
        domain_band=raw_band,
        domain_band_display=band_display,
        counts=counts,
    )


def format_duration(started_at: datetime | None, finished_at: datetime | None) -> str:
    """Format execution duration between started and finished timestamps."""
    if not started_at:
        return "--"
    if not finished_at:
        return "In progress"
    duration_secs = max(0, int((finished_at - started_at).total_seconds()))
    if duration_secs < 60:
        return f"{duration_secs}s"
    minutes = duration_secs // 60
    secs = duration_secs % 60
    return f"{minutes}m {secs}s"


CHANGE_TIERS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def format_change_summary(change_detection: dict[str, Any] | None) -> str:
    """Summarize scan_runs.change_detection JSON for table rows.

    The worker writes counts as {"critical", "high", "medium", "low", "info"} with no
    "total" key (see worker.py change detection), so the total is the sum of the tiers.
    Non-integer values are ignored.
    """
    if not isinstance(change_detection, dict):
        return "--"
    status = change_detection.get("status")
    if status == "baseline":
        return "Baseline scan"
    if status == "computed":
        counts = change_detection.get("counts")
        if not isinstance(counts, dict):
            return "Changes detected"
        tier_counts = []
        for tier in CHANGE_TIERS:
            value = counts.get(tier, 0)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                tier_counts.append((tier, value))
        if not tier_counts:
            return "No changes"
        return ", ".join(f"{value} {tier}" for tier, value in tier_counts)
    if status == "failed":
        return "Detection error"
    return "--"


def check_polling_status(
    status: str,
    created_at: datetime | None,
    now: datetime | None = None,
) -> tuple[bool, bool]:
    """Determine whether scan detail fragment should poll and whether it is stale.

    Returns:
        (should_poll, is_stale_active)
    """
    if status not in ("queued", "running"):
        return False, False

    if now is None:
        now = datetime.now(UTC)

    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)

    age_seconds = (now - created_at).total_seconds() if created_at else 0
    if age_seconds < 15 * 60:
        return True, False
    return False, True
