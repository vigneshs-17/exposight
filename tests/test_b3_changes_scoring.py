"""v3.6c B-3: change detection (bugs c, d, e) and domain-level scoring findings (bug f)."""

from asm.changes import detect_changes
from asm.scoring import LARGE_ATTACK_SURFACE_THRESHOLD, score_domain_payloads
from asm.ui_views import extract_fix_first_findings

HOST = "api.example.com"
STRONG_HSTS = {"Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"}


def _probe(host: str, https_reachable: bool, error_type: str | None = None) -> dict:
    https = {"reachable": https_reachable, "status_code": 200 if https_reachable else None}
    if error_type:
        https["error_type"] = error_type
    return {
        "subdomain": host,
        "status": "PROBED",
        "http": {"reachable": True, "status_code": 200},
        "https": https,
    }


def _scan(stamp: str, probe=None, inspect=None) -> dict:
    report = {"score": {"generated_utc": stamp}}
    if probe is not None:
        report["probe"] = {"results": probe}
    if inspect is not None:
        report["inspect"] = {"results": inspect}
    return report


def _types(changes: list[dict]) -> list[str]:
    return sorted(c["change_type"] for c in changes)


# --- bug c: HTTPS_LOST only after a real loss -----------------------------------------

def test_https_lost_when_baseline_reached_https():
    base = _scan("2026-10-01T08:00:00Z", probe=[_probe(HOST, True)])
    new = _scan("2026-10-01T09:00:00Z", probe=[_probe(HOST, False, "CONNECT_ERROR")])
    assert _types(detect_changes(base, new)) == ["HTTPS_LOST"]


def test_no_https_lost_for_a_host_new_in_this_scan():
    base = _scan("2026-10-01T08:00:00Z", probe=[])
    new = _scan("2026-10-01T09:00:00Z", probe=[_probe("new.example.com", False, "CONNECT_ERROR")])
    assert "HTTPS_LOST" not in _types(detect_changes(base, new))


def test_no_https_lost_when_baseline_never_reached_https():
    base_entry = _probe(HOST, False, "CONNECT_ERROR")
    base_entry["http"] = {"reachable": False}  # unreachable last time: no HTTP_NO_HTTPS either
    base = _scan("2026-10-01T08:00:00Z", probe=[base_entry])
    new = _scan("2026-10-01T09:00:00Z", probe=[_probe(HOST, False, "CONNECT_ERROR")])
    assert "HTTPS_LOST" not in _types(detect_changes(base, new))


# --- bug d: weak HSTS is "weakened", not "removed" ------------------------------------

def _inspect(host: str, present: dict, missing: list, *, hsts_weak=False, status="PROBED"):
    headers = {"present_headers": present, "missing_headers": missing}
    if hsts_weak:
        headers.update({"hsts_weak": True, "hsts_max_age": 300})
    return {"subdomain": host, "status": status, "headers": headers}


def test_strong_to_weak_hsts_is_weakened():
    base = _scan("2026-10-01T08:00:00Z", inspect=[_inspect(HOST, STRONG_HSTS, [])])
    weak = {**STRONG_HSTS, "Strict-Transport-Security": "max-age=300"}
    new = _scan("2026-10-01T09:00:00Z", inspect=[_inspect(HOST, weak, [], hsts_weak=True)])
    changes = detect_changes(base, new)
    assert _types(changes) == ["SECURITY_HEADER_WEAKENED"]
    assert changes[0]["detail"] == "Strict-Transport-Security"


def test_missing_to_weak_hsts_is_an_addition_not_a_weakening():
    base = _scan(
        "2026-10-01T08:00:00Z",
        inspect=[_inspect(HOST, {"X-Frame-Options": "DENY"}, ["Strict-Transport-Security"])],
    )
    weak = {**STRONG_HSTS, "Strict-Transport-Security": "max-age=300"}
    new = _scan("2026-10-01T09:00:00Z", inspect=[_inspect(HOST, weak, [], hsts_weak=True)])
    assert _types(detect_changes(base, new)) == ["SECURITY_HEADER_ADDED"]


def test_missing_header_still_reported_as_removed():
    base = _scan("2026-10-01T08:00:00Z", inspect=[_inspect(HOST, STRONG_HSTS, [])])
    new = _scan(
        "2026-10-01T09:00:00Z",
        inspect=[_inspect(HOST, {"X-Frame-Options": "DENY"}, ["Strict-Transport-Security"])],
    )
    assert _types(detect_changes(base, new)) == ["SECURITY_HEADER_REMOVED"]


# --- bug e: only hosts inspected in BOTH scans are diffed -----------------------------

def test_new_host_with_missing_headers_reports_no_header_changes():
    base = _scan("2026-10-01T08:00:00Z", inspect=[])
    new = _scan(
        "2026-10-01T09:00:00Z",
        inspect=[_inspect("new.example.com", {}, ["Strict-Transport-Security"])],
    )
    assert detect_changes(base, new) == []


def test_host_unreachable_in_baseline_reports_no_header_changes():
    base = _scan(
        "2026-10-01T08:00:00Z",
        inspect=[{"subdomain": HOST, "status": "SKIPPED_UNRESOLVED", "headers": None}],
    )
    new = _scan("2026-10-01T09:00:00Z", inspect=[_inspect(HOST, {}, ["Strict-Transport-Security"])])
    assert detect_changes(base, new) == []


# --- bug f: LARGE_ATTACK_SURFACE survives without the apex host -----------------------

def _discovered(count: int) -> list[dict]:
    return [{"subdomain": f"h{i}.example.com"} for i in range(count)]


def test_large_attack_surface_kept_when_apex_not_discovered():
    report = score_domain_payloads("example.com", _discovered(LARGE_ATTACK_SURFACE_THRESHOLD))
    assert "example.com" not in {h.subdomain for h in report.hosts}
    assert [f.id for f in report.domain_findings] == ["LARGE_ATTACK_SURFACE"]
    assert report.counts["findings_info"] == 1

    as_dict = report.to_dict()
    assert as_dict["domain_findings"][0]["id"] == "LARGE_ATTACK_SURFACE"

    ui = extract_fix_first_findings(as_dict)
    assert [(f.id, f.host) for f in ui.findings] == [("LARGE_ATTACK_SURFACE", "example.com")]
    assert ui.counts["INFO"] == 1


def test_large_attack_surface_reported_once_when_apex_is_a_host():
    hosts = _discovered(LARGE_ATTACK_SURFACE_THRESHOLD) + [{"subdomain": "example.com"}]
    report = score_domain_payloads("example.com", hosts)
    ids = [f.id for h in report.hosts for f in h.findings] + [
        f.id for f in report.domain_findings
    ]
    assert ids.count("LARGE_ATTACK_SURFACE") == 1


def test_small_surface_has_no_domain_findings():
    report = score_domain_payloads("example.com", _discovered(3))
    assert report.domain_findings == []


def test_old_score_reports_without_domain_findings_still_render():
    old_report = {"domain": "example.com", "domain_score": 0, "domain_band": "INFO", "hosts": []}
    ui = extract_fix_first_findings(old_report)
    assert ui.findings == [] and ui.total == 0
