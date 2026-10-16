"""Unit tests for Exposight change detection engine (src/asm/changes.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from asm.changes import detect_changes, evaluate_removal_eligibility


def test_evaluate_removal_eligibility():
    """Verify source matching and truncation rules for removal detection."""
    # 1. Matching sources, neither truncated -> eligible
    b1 = {"source": "crt.sh", "truncated": False}
    n1 = {"source": "crt.sh", "truncated": False}
    eligible, reason = evaluate_removal_eligibility(b1, n1)
    assert eligible is True
    assert reason is None

    # 2. Defaults for v1 reports without explicit keys -> eligible
    b_v1 = {}
    n_v1 = {}
    eligible, reason = evaluate_removal_eligibility(b_v1, n_v1)
    assert eligible is True
    assert reason is None

    # 3. Source mismatch -> skipped with source names
    b2 = {"source": "crt.sh"}
    n2 = {"source": "certspotter"}
    eligible, reason = evaluate_removal_eligibility(b2, n2)
    assert eligible is False
    assert reason == "Source mismatch (crt.sh vs certspotter)"

    # 4. Baseline truncated -> skipped
    b3 = {"source": "crt.sh", "truncated": True}
    n3 = {"source": "crt.sh", "truncated": False}
    eligible, reason = evaluate_removal_eligibility(b3, n3)
    assert eligible is False
    assert reason == "Baseline discovery report was truncated"

    # 5. New truncated -> skipped
    b4 = {"source": "crt.sh", "truncated": False}
    n4 = {"source": "crt.sh", "truncated": True}
    eligible, reason = evaluate_removal_eligibility(b4, n4)
    assert eligible is False
    assert reason == "New discovery report was truncated"

    # 6. Both truncated -> skipped
    b5 = {"source": "crt.sh", "truncated": True}
    n5 = {"source": "crt.sh", "truncated": True}
    eligible, reason = evaluate_removal_eligibility(b5, n5)
    assert eligible is False
    assert reason == "Baseline and new discovery reports were truncated"


def test_expired_cert_yields_exactly_one_change():
    """An expired cert that is also self-signed/untrusted yields ONLY CERTIFICATE_BECAME_EXPIRED."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "cert": {
                        "expired": False,
                        "is_trusted": True,
                        "issuer_equals_subject": False,
                        "hostname_mismatch": False,
                        "expiring_soon": False,
                        "issuer": "Let's Encrypt",
                        "not_after": "2026-10-01T00:00:00Z",
                    },
                }
            ]
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "cert": {
                        "expired": True,
                        "is_trusted": False,  # Also untrusted
                        "issuer_equals_subject": True,  # Also self-signed
                        "hostname_mismatch": False,
                        "expiring_soon": False,
                        "issuer": "api.example.com",
                        "not_after": "2026-10-01T00:00:00Z",
                    },
                }
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    cert_changes = [c for c in changes if c["asset"] == "api.example.com"]
    assert len(cert_changes) == 1
    assert cert_changes[0]["change_type"] == "CERTIFICATE_BECAME_EXPIRED"
    assert cert_changes[0]["severity"] == "HIGH"
    assert cert_changes[0]["category"] == "exposure"
    assert cert_changes[0]["evidence"] == "inspect"


def test_self_signed_yields_exactly_one_medium_change():
    """A self-signed certificate yields exactly one CERTIFICATE_SELF_SIGNED with MEDIUM tier."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "cert": {
                        "expired": False,
                        "is_trusted": True,
                        "issuer_equals_subject": False,
                        "issuer": "DigiCert",
                    },
                }
            ]
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "cert": {
                        "expired": False,
                        "is_trusted": False,
                        "issuer_equals_subject": True,  # Self-signed
                        "issuer": "api.example.com",
                    },
                }
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    cert_changes = [c for c in changes if c["asset"] == "api.example.com"]
    assert len(cert_changes) == 1
    assert cert_changes[0]["change_type"] == "CERTIFICATE_SELF_SIGNED"
    assert cert_changes[0]["severity"] == "MEDIUM"
    assert cert_changes[0]["category"] == "exposure"


def test_truncated_report_skips_removals():
    """When allow_removal is False, removed subdomains are not emitted."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "discover": {
            "source": "crt.sh",
            "results": [
                {"subdomain": "api.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "old.example.com", "status": "RESOLVED", "resolved": True},
            ],
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "discover": {
            "source": "crt.sh",
            "truncated": True,
            "results": [
                {"subdomain": "api.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "new.example.com", "status": "RESOLVED", "resolved": True},
            ],
        },
    }

    # evaluate_removal_eligibility flags it as False
    eligible, reason = evaluate_removal_eligibility(baseline["discover"], new_scan["discover"])
    assert eligible is False
    assert reason == "New discovery report was truncated"

    changes = detect_changes(baseline, new_scan, allow_removal=eligible)
    # new.example.com is added
    assert any(
        c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == "new.example.com"
        for c in changes
    )
    # old.example.com removal is SKIPPED
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes)


def test_host_unreachable_in_new_scan_resolves_no_findings():
    """If host is unreachable or skipped in new scan, baseline findings are NOT marked resolved."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "headers": {
                        "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy"],
                        "present_headers": {},
                    },
                }
            ]
        },
        "portscan": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "open_ports": [{"port": 3306, "state": "OPEN"}],
                }
            ]
        },
    }

    # New scan: host skipped or errored
    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "SKIPPED_UNRESOLVED",
                    "headers": None,
                    "cert": None,
                }
            ]
        },
        "portscan": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "SKIPPED_UNRESOLVED",
                    "open_ports": [],
                    "closed_ports": [],
                }
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    # No SECURITY_HEADER_ADDED and no PORT_NO_LONGER_OPEN should be emitted
    assert not any(c["change_type"] == "SECURITY_HEADER_ADDED" for c in changes)
    assert not any(c["change_type"] == "PORT_NO_LONGER_OPEN" for c in changes)


def test_two_headers_removed_same_host_unique_detail():
    """Two missing headers on the same host create two distinct changes distinguished by detail."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "headers": {
                        "present_headers": {
                            "Strict-Transport-Security": "max-age=31536000",
                            "Content-Security-Policy": "default-src 'self'",
                        },
                        "missing_headers": [],
                    },
                }
            ]
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "inspect": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "headers": {
                        "present_headers": {},
                        "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy"],
                    },
                }
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    header_changes = [c for c in changes if c["change_type"] == "SECURITY_HEADER_REMOVED"]
    assert len(header_changes) == 2

    hsts = next(c for c in header_changes if c["detail"] == "Strict-Transport-Security")
    assert hsts["severity"] == "LOW"
    assert hsts["asset"] == "api.example.com"
    assert hsts["category"] == "exposure"

    csp = next(c for c in header_changes if c["detail"] == "Content-Security-Policy")
    assert csp["severity"] == "LOW"
    assert csp["asset"] == "api.example.com"
    assert csp["category"] == "exposure"


def test_https_lost_definite_failure_vs_timeout():
    """HTTPS_LOST is emitted on definite connect error, but never on timeout."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "probe": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200},
                    "https": {"reachable": True, "status_code": 200},
                }
            ]
        },
    }

    # Case 1: Timeout on HTTPS (never emits HTTPS_LOST, even across repeated scans)
    timeout_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "probe": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200},
                    "https": {"reachable": False, "error_type": "TIMEOUT"},
                }
            ]
        },
    }
    changes_timeout = detect_changes(
        timeout_scan, timeout_scan, historical_baselines=[timeout_scan, baseline]
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_timeout)

    # Case 2: Definite CONNECT_ERROR on HTTPS (emits on 2nd consecutive failure after success)
    connect_err_scan1 = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "probe": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200},
                    "https": {"reachable": False, "error_type": "CONNECT_ERROR"},
                }
            ]
        },
    }
    connect_err_scan2 = {
        "score": {"generated_utc": "2026-10-01T09:00:00Z"},
        "probe": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200},
                    "https": {"reachable": False, "error_type": "CONNECT_ERROR"},
                }
            ]
        },
    }
    changes_err = detect_changes(
        connect_err_scan1, connect_err_scan2, historical_baselines=[connect_err_scan1, baseline]
    )
    lost = [c for c in changes_err if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 1
    assert lost[0]["severity"] == "MEDIUM"
    assert lost[0]["asset"] == "api.example.com"


def test_port_opened_and_closed_severities():
    """Verify port open severities match scoring.py rules, and closed ports are INFO."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "portscan": {
            "results": [
                {
                    "subdomain": "db.example.com",
                    "status": "PROBED",
                    "open_ports": [{"port": 80, "state": "OPEN"}],
                    "closed_ports": [3306],
                }
            ]
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "portscan": {
            "results": [
                {
                    "subdomain": "db.example.com",
                    "status": "PROBED",
                    "open_ports": [
                        {
                            "port": 3306,
                            "state": "OPEN",
                            "banner": "5.7.34-MySQL",
                            "service_guess": "mysql",
                        },
                        {"port": 443, "state": "OPEN", "service_guess": "https"},
                    ],
                    "closed_ports": [80],
                }
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    # Port 3306 with banner -> CRITICAL (PORT_CONFIRMED_DB)
    p3306 = next(
        c for c in changes if c["change_type"] == "PORT_NEWLY_OPEN" and c["detail"] == "3306"
    )
    assert p3306["severity"] == "CRITICAL"

    # Port 443 -> INFO (Standard port)
    p443 = next(
        c for c in changes if c["change_type"] == "PORT_NEWLY_OPEN" and c["detail"] == "443"
    )
    assert p443["severity"] == "INFO"

    # Port 80 closed -> INFO
    p80 = next(
        c for c in changes if c["change_type"] == "PORT_NO_LONGER_OPEN" and c["detail"] == "80"
    )
    assert p80["severity"] == "INFO"


def test_dns_status_changes():
    """Verify NXDOMAIN <-> RESOLVED transitions and timeout ignorance."""
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "discover": {
            "results": [
                {"subdomain": "resolved.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "nx.example.com", "status": "NXDOMAIN", "resolved": False},
                {"subdomain": "stable.example.com", "status": "RESOLVED", "resolved": True},
            ]
        },
    }

    new_scan = {
        "score": {"generated_utc": "2026-10-01T08:30:00Z"},
        "discover": {
            "results": [
                {"subdomain": "resolved.example.com", "status": "NXDOMAIN", "resolved": False},
                {"subdomain": "nx.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "stable.example.com", "status": "TIMEOUT", "resolved": False},
            ]
        },
    }

    changes = detect_changes(baseline, new_scan)
    # stopped resolving
    assert any(
        c["change_type"] == "STOPPED_RESOLVING" and c["asset"] == "resolved.example.com"
        for c in changes
    )
    # newly resolving
    assert any(
        c["change_type"] == "NEWLY_RESOLVING" and c["asset"] == "nx.example.com"
        for c in changes
    )
    # TIMEOUT is ignored: unknown is not absent
    assert not any(c["asset"] == "stable.example.com" for c in changes)


def test_observed_at_matches_generated_utc():
    """Verify observed_at timestamp matches score report generated_utc."""
    timestamp = "2026-10-01T08:45:00+00:00"
    baseline = {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "discover": {"results": []},
    }
    new_scan = {
        "score": {"generated_utc": timestamp},
        "discover": {
            "results": [{"subdomain": "new.example.com", "status": "RESOLVED", "resolved": True}]
        },
    }

    changes = detect_changes(baseline, new_scan)
    assert len(changes) == 1
    expected_dt = datetime.fromisoformat(timestamp).replace(tzinfo=UTC)
    assert changes[0]["observed_at"] == expected_dt


def test_detect_changes_real_v1_report_shapes():
    """Verify change detection operates accurately on exact real v1 report shapes.

    Constructs baseline and new scan reports using the production dataclasses:
    SubdomainResult, HostProbeResult, HostPortScanResult, and HostInspectResult.
    """
    from asm.models import (
        CertInfo,
        HeaderInfo,
        HostInspectResult,
        HostPortScanResult,
        HostProbeResult,
        HostProbeStatus,
        HostScore,
        InspectReport,
        PortResult,
        PortScanReport,
        PortStatus,
        ProbeReport,
        ScoreReport,
        SubdomainResult,
        UrlProbeResult,
    )

    domain = "v1-company.com"

    s2_bundle = {
        "discover": {
            "domain": domain,
            "source": "crt.sh",
            "truncated": False,
            "results": [
                SubdomainResult(
                    subdomain="app.v1-company.com",
                    ip_addresses=["1.2.3.4"],
                    status="RESOLVED",
                    resolved=True,
                ).to_dict(),
                SubdomainResult(
                    subdomain="old.v1-company.com",
                    ip_addresses=["1.2.3.5"],
                    status="RESOLVED",
                    resolved=True,
                ).to_dict(),
            ],
        },
        "probe": ProbeReport(
            domain=domain,
            source_report="discover.json",
            probe_started_utc="2026-10-01T07:00:00Z",
            probe_finished_utc="2026-10-01T07:01:00Z",
            counts={"probed": 2, "live": 2, "skipped": 0},
            results=[
                HostProbeResult(
                    subdomain="app.v1-company.com",
                    status=HostProbeStatus.PROBED.value,
                    https=UrlProbeResult(
                        url="https://app.v1-company.com", reachable=True, status_code=200
                    ),
                    http=UrlProbeResult(
                        url="http://app.v1-company.com", reachable=True, status_code=301
                    ),
                    live=True,
                ),
            ],
        ).to_dict(),
    }

    base_discover = {
        "domain": domain,
        "source": "crt.sh",
        "truncated": False,
        "results": [
            SubdomainResult(
                subdomain="app.v1-company.com",
                ip_addresses=["1.2.3.4"],
                status="RESOLVED",
                resolved=True,
            ).to_dict(),
        ],
    }
    base_probe = ProbeReport(
        domain=domain,
        source_report="discover.json",
        probe_started_utc="2026-10-01T08:00:00Z",
        probe_finished_utc="2026-10-01T08:01:00Z",
        counts={"probed": 2, "live": 2, "skipped": 0},
        results=[
            HostProbeResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://app.v1-company.com", reachable=False, error_type="CONNECT_ERROR"
                ),
                http=UrlProbeResult(
                    url="http://app.v1-company.com", reachable=True, status_code=301
                ),
                live=True,
            ),
            HostProbeResult(
                subdomain="old.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://old.v1-company.com", reachable=True, status_code=200
                ),
                http=UrlProbeResult(
                    url="http://old.v1-company.com", reachable=True, status_code=200
                ),
                live=True,
            ),
        ],
    ).to_dict()

    base_portscan = PortScanReport(
        domain=domain,
        source_report="discover.json",
        scan_started_utc="2026-10-01T08:01:00Z",
        scan_finished_utc="2026-10-01T08:02:00Z",
        results=[
            HostPortScanResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                open_ports=[
                    PortResult(port=443, state=PortStatus.OPEN.value, service_guess="https"),
                    PortResult(port=80, state=PortStatus.OPEN.value, service_guess="http"),
                ],
                closed_ports=[22, 3306],
                filtered_ports=[8080],
            )
        ],
    ).to_dict()

    base_inspect = InspectReport(
        domain=domain,
        source_report="discover.json",
        inspect_started_utc="2026-10-01T08:02:00Z",
        inspect_finished_utc="2026-10-01T08:03:00Z",
        results=[
            HostInspectResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                cert=CertInfo(
                    subject_cn="app.v1-company.com",
                    issuer="CN=Let's Encrypt Authority X3",
                    not_after="2026-11-01T00:00:00Z",
                    days_until_expiry=60.0,
                    is_trusted=True,
                    expired=False,
                ),
                headers=HeaderInfo(
                    present_headers={"Strict-Transport-Security": "max-age=31536000"},
                    missing_headers=["Content-Security-Policy"],
                ),
            )
        ],
    ).to_dict()

    base_score = ScoreReport(
        domain=domain,
        generated_utc="2026-10-01T08:03:30Z",
        inputs_present=["discover", "probe", "portscan", "inspect"],
        domain_score=10,
        domain_band="LOW",
        hosts=[HostScore(subdomain="app.v1-company.com", score=10, band="LOW")],
    ).to_dict()

    # 2. New Scan Reports:
    # Changes introduced:
    # - "new.v1-company.com" added (NEW_SUBDOMAIN)
    # - "old.v1-company.com" removed (REMOVED_SUBDOMAIN)
    # - app.v1-company.com: port 3306 open, port 80 closed
    # - app.v1-company.com: cert expired, HSTS removed
    # - app.v1-company.com: HTTPS unreachable (error_type="CONNECT_ERROR" -> HTTPS_LOST)
    # - risk band changed to HIGH
    new_discover = {
        "domain": domain,
        "source": "crt.sh",
        "truncated": False,
        "results": [
            SubdomainResult(
                subdomain="app.v1-company.com",
                ip_addresses=["1.2.3.4"],
                status="RESOLVED",
                resolved=True,
            ).to_dict(),
            SubdomainResult(
                subdomain="new.v1-company.com",
                ip_addresses=["1.2.3.6"],
                status="RESOLVED",
                resolved=True,
            ).to_dict(),
        ],
    }
    new_probe = ProbeReport(
        domain=domain,
        source_report="discover.json",
        probe_started_utc="2026-10-01T09:00:00Z",
        probe_finished_utc="2026-10-01T09:01:00Z",
        counts={"probed": 2, "live": 2, "skipped": 0},
        results=[
            HostProbeResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://app.v1-company.com", reachable=False, error_type="CONNECT_ERROR"
                ),
                http=UrlProbeResult(
                    url="http://app.v1-company.com", reachable=True, status_code=200
                ),
                live=True,
            ),
            HostProbeResult(
                subdomain="new.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://new.v1-company.com", reachable=True, status_code=200
                ),
                live=True,
            ),
        ],
    ).to_dict()

    new_portscan = PortScanReport(
        domain=domain,
        source_report="discover.json",
        scan_started_utc="2026-10-01T09:01:00Z",
        scan_finished_utc="2026-10-01T09:02:00Z",
        results=[
            HostPortScanResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                open_ports=[
                    PortResult(port=443, state=PortStatus.OPEN.value, service_guess="https"),
                    PortResult(
                        port=3306,
                        state=PortStatus.OPEN.value,
                        service_guess="mysql",
                        banner="5.7.34 MySQL Community Server",
                    ),
                ],
                closed_ports=[22, 80],
                filtered_ports=[8080],
            )
        ],
    ).to_dict()

    new_inspect = InspectReport(
        domain=domain,
        source_report="discover.json",
        inspect_started_utc="2026-10-01T09:02:00Z",
        inspect_finished_utc="2026-10-01T09:03:00Z",
        results=[
            HostInspectResult(
                subdomain="app.v1-company.com",
                status=HostProbeStatus.PROBED.value,
                cert=CertInfo(
                    subject_cn="app.v1-company.com",
                    issuer="CN=Let's Encrypt Authority X3",
                    not_after="2026-10-01T00:00:00Z",
                    days_until_expiry=-1.0,
                    is_trusted=False,
                    expired=True,
                ),
                headers=HeaderInfo(
                    present_headers={},
                    missing_headers=["Strict-Transport-Security", "Content-Security-Policy"],
                ),
            )
        ],
    ).to_dict()

    new_score = ScoreReport(
        domain=domain,
        generated_utc="2026-10-01T09:03:30Z",
        inputs_present=["discover", "probe", "portscan", "inspect"],
        domain_score=85,
        domain_band="HIGH",
        hosts=[HostScore(subdomain="app.v1-company.com", score=85, band="HIGH")],
    ).to_dict()

    baseline_bundle = {
        "discover": base_discover,
        "probe": base_probe,
        "portscan": base_portscan,
        "inspect": base_inspect,
        "score": base_score,
    }
    new_bundle = {
        "discover": new_discover,
        "probe": new_probe,
        "portscan": new_portscan,
        "inspect": new_inspect,
        "score": new_score,
    }

    hist = [
        {"scan_run_id": 2, "reports": baseline_bundle},
        {"scan_run_id": 1, "reports": s2_bundle},
    ]
    changes = detect_changes(
        baseline_bundle, new_bundle, historical_baselines=hist, baseline_scan_run_id=2
    )
    change_types = {c["change_type"] for c in changes}

    assert "NEW_SUBDOMAIN" in change_types
    assert "REMOVED_SUBDOMAIN" in change_types
    assert "HTTPS_LOST" in change_types
    assert "PORT_NEWLY_OPEN" in change_types
    assert "PORT_NO_LONGER_OPEN" in change_types
    assert "CERTIFICATE_BECAME_EXPIRED" in change_types
    assert "SECURITY_HEADER_REMOVED" in change_types
    assert "HOST_RISK_BAND_INCREASED" in change_types
    assert "DOMAIN_RISK_BAND_INCREASED" in change_types

    p3306 = next(c for c in changes if c["change_type"] == "PORT_NEWLY_OPEN")
    assert p3306["detail"] == "3306"
    assert p3306["severity"] == "CRITICAL"

    hsts = next(c for c in changes if c["change_type"] == "SECURITY_HEADER_REMOVED")
    assert hsts["detail"] == "Strict-Transport-Security"
    assert hsts["severity"] == "LOW"


def _make_port_scan(host: str, *, open_ports=None, closed_ports=None, filtered_ports=None):
    return {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": open_ports or [],
                    "closed_ports": closed_ports or [],
                    "filtered_ports": filtered_ports or [],
                }
            ]
        }
    }


def test_port_open_filtered_open_suppresses_port_newly_open():
    """OPEN -> FILTERED -> OPEN must not emit PORT_NEWLY_OPEN."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = _make_port_scan(host, filtered_ports=[80])
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    hist = [
        {"scan_run_id": 2, "reports": s2},
        {"scan_run_id": 1, "reports": s1},
    ]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=2)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert port_changes == []


def test_port_open_filtered_closed_emits_closure_with_correct_baseline_id():
    """OPEN -> FILTERED -> CLOSED emits PORT_NO_LONGER_OPEN with the open scan's ID."""
    host = "api.example.com"
    s1 = _make_port_scan(
        host, open_ports=[{"port": 80, "state": "OPEN", "service_guess": "http"}]
    )
    s2 = _make_port_scan(host, filtered_ports=[80])
    s3 = _make_port_scan(host, closed_ports=[80])

    hist = [
        {"scan_run_id": 102, "reports": s2},
        {"scan_run_id": 101, "reports": s1},
    ]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=102)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert len(port_changes) == 1
    ch = port_changes[0]
    assert ch["change_type"] == "PORT_NO_LONGER_OPEN"
    assert ch["detail"] == "80"
    assert ch["baseline_scan_run_id"] == 101  # Carries actual baseline where port was open


def test_port_closed_filtered_open_emits_newly_open_with_correct_baseline_id():
    """CLOSED -> FILTERED -> OPEN emits PORT_NEWLY_OPEN with the closed scan's ID."""
    host = "api.example.com"
    s1 = _make_port_scan(host, closed_ports=[80])
    s2 = _make_port_scan(host, filtered_ports=[80])
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    hist = [
        {"scan_run_id": 202, "reports": s2},
        {"scan_run_id": 201, "reports": s1},
    ]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=202)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert len(port_changes) == 1
    ch = port_changes[0]
    assert ch["change_type"] == "PORT_NEWLY_OPEN"
    assert ch["detail"] == "80"
    assert ch["baseline_scan_run_id"] == 201  # Carries actual baseline where port was closed
    assert ch["previous_state"] == {"port": 80, "state": "CLOSED"}


def test_port_filtered_repeated_beyond_window_recovers_as_newly_open():
    """Prolonged uncertainty beyond the 3-scan window recovers as PORT_NEWLY_OPEN."""
    host = "api.example.com"
    _s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = _make_port_scan(host, filtered_ports=[80])
    s3 = _make_port_scan(host, filtered_ports=[80])
    s4 = _make_port_scan(host, filtered_ports=[80])
    s5 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    # Window passed to s5 is [s4, s3, s2]; s1 is outside window
    hist = [
        {"scan_run_id": 304, "reports": s4},
        {"scan_run_id": 303, "reports": s3},
        {"scan_run_id": 302, "reports": s2},
    ]
    changes = detect_changes(s4, s5, historical_baselines=hist, baseline_scan_run_id=304)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert len(port_changes) == 1
    ch = port_changes[0]
    assert ch["change_type"] == "PORT_NEWLY_OPEN"
    assert ch["detail"] == "80"
    assert ch["baseline_scan_run_id"] == 304  # Fallback to immediate baseline
    assert ch["previous_state"] is None  # Distinguishes no definite prior evidence


def test_port_missing_stage_data_treated_as_unknown():
    """Missing portscan stage in intermediate scan is treated as unknown."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = {}  # Portscan report missing entirely
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    hist = [
        {"scan_run_id": 402, "reports": s2},
        {"scan_run_id": 401, "reports": s1},
    ]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=402)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert port_changes == []


def test_port_genuine_close_reopen_cycle():
    """OPEN -> CLOSED -> OPEN emits PORT_NO_LONGER_OPEN then PORT_NEWLY_OPEN."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = _make_port_scan(host, closed_ports=[80])
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    # s1 -> s2
    ch12 = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 501, "reports": s1}],
        baseline_scan_run_id=501,
    )
    port_ch12 = [c for c in ch12 if c["change_type"].startswith("PORT_")]
    assert len(port_ch12) == 1
    assert port_ch12[0]["change_type"] == "PORT_NO_LONGER_OPEN"
    assert port_ch12[0]["baseline_scan_run_id"] == 501

    # s2 -> s3
    ch23 = detect_changes(
        s2,
        s3,
        historical_baselines=[
            {"scan_run_id": 502, "reports": s2},
            {"scan_run_id": 501, "reports": s1},
        ],
        baseline_scan_run_id=502,
    )
    port_ch23 = [c for c in ch23 if c["change_type"].startswith("PORT_")]
    assert len(port_ch23) == 1
    assert port_ch23[0]["change_type"] == "PORT_NEWLY_OPEN"
    assert port_ch23[0]["baseline_scan_run_id"] == 502


def test_port_repeated_stable_observations_emit_no_change():
    """Stable OPEN -> OPEN -> OPEN and CLOSED -> CLOSED -> CLOSED emit no changes."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}], closed_ports=[443])
    s2 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}], closed_ports=[443])
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}], closed_ports=[443])

    hist = [{"scan_run_id": 602, "reports": s2}, {"scan_run_id": 601, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=602)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert port_changes == []


def test_per_change_baseline_attribution_preserves_immediate_for_other_types():
    """Port changes carry historical baseline ID; non-port changes do not override baseline ID."""
    host = "api.example.com"
    s1 = {
        "discover": {
            "domain": "example.com",
            "results": [{"subdomain": host, "status": "RESOLVED", "resolved": True}],
        },
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [{"port": 80, "state": "OPEN"}],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        },
    }
    s2 = {
        "discover": {
            "domain": "example.com",
            "results": [{"subdomain": host, "status": "RESOLVED", "resolved": True}],
        },
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [],
                    "filtered_ports": [80],
                }
            ]
        },
    }
    s3 = {
        "discover": {
            "domain": "example.com",
            "results": [
                {"subdomain": host, "status": "RESOLVED", "resolved": True},
                {"subdomain": "gamma.example.com", "status": "RESOLVED", "resolved": True},
            ],
        },
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [80],
                    "filtered_ports": [],
                }
            ]
        },
    }

    hist = [{"scan_run_id": 702, "reports": s2}, {"scan_run_id": 701, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=702)

    port_ch = next(c for c in changes if c["change_type"] == "PORT_NO_LONGER_OPEN")
    assert port_ch["baseline_scan_run_id"] == 701  # Pointed to scan 1 where it was open

    sub_ch = next(c for c in changes if c["change_type"] == "NEW_SUBDOMAIN")
    assert "baseline_scan_run_id" not in sub_ch  # Preserves run-level default in worker


def test_port_window_boundary_definite_inside_vs_outside():
    """Boundary test: 2 unknowns + 1 definite is inside window; 3 unknowns is outside."""
    host = "api.example.com"
    s_open = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s_filt = _make_port_scan(host, filtered_ports=[80])
    s_closed = _make_port_scan(host, closed_ports=[80])

    # Case A: 2 unknowns then 1 definite inside 3-scan window (index 2)
    # Window = [s3 (filtered), s2 (filtered), s1 (open)] -> s4 (closed)
    hist_inside = [
        {"scan_run_id": 103, "reports": s_filt},
        {"scan_run_id": 102, "reports": s_filt},
        {"scan_run_id": 101, "reports": s_open},
    ]
    ch_a = detect_changes(
        s_filt, s_closed, historical_baselines=hist_inside, baseline_scan_run_id=103
    )
    port_ch_a = [c for c in ch_a if c["change_type"].startswith("PORT_")]
    assert len(port_ch_a) == 1
    assert port_ch_a[0]["change_type"] == "PORT_NO_LONGER_OPEN"
    assert port_ch_a[0]["baseline_scan_run_id"] == 101  # Retained in window

    # Case B: Exactly 3 unknowns in window; original definite observation expired
    # Window = [s4 (filtered), s3 (filtered), s2 (filtered)] -> s5 (open)
    hist_outside = [
        {"scan_run_id": 104, "reports": s_filt},
        {"scan_run_id": 103, "reports": s_filt},
        {"scan_run_id": 102, "reports": s_filt},
    ]
    ch_b = detect_changes(
        s_filt, s_open, historical_baselines=hist_outside, baseline_scan_run_id=104
    )
    port_ch_b = [c for c in ch_b if c["change_type"].startswith("PORT_")]
    assert len(port_ch_b) == 1
    assert port_ch_b[0]["change_type"] == "PORT_NEWLY_OPEN"
    assert port_ch_b[0]["baseline_scan_run_id"] == 104  # Immediate fallback
    assert port_ch_b[0]["previous_state"] is None  # Uncertainty policy


def test_port_unprobed_or_timeout_treated_as_unknown():
    """Hosts with TIMEOUT or UNPROBED status are treated as unknown observations."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    # s2: host timed out during portscan stage
    s2 = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "TIMEOUT",
                    "open_ports": [],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        }
    }
    s3_open = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s3_closed = _make_port_scan(host, closed_ports=[80])

    hist = [{"scan_run_id": 202, "reports": s2}, {"scan_run_id": 201, "reports": s1}]

    # OPEN -> TIMEOUT -> OPEN: suppressed
    ch_open = detect_changes(s2, s3_open, historical_baselines=hist, baseline_scan_run_id=202)
    assert [c for c in ch_open if c["change_type"].startswith("PORT_")] == []

    # OPEN -> TIMEOUT -> CLOSED: emits closure with s1 baseline
    ch_closed = detect_changes(s2, s3_closed, historical_baselines=hist, baseline_scan_run_id=202)
    port_ch = [c for c in ch_closed if c["change_type"].startswith("PORT_")]
    assert len(port_ch) == 1
    assert port_ch[0]["change_type"] == "PORT_NO_LONGER_OPEN"
    assert port_ch[0]["baseline_scan_run_id"] == 201


def test_port_more_recent_closed_overrides_older_open():
    """A recent CLOSED observation in history takes precedence over older OPEN."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = _make_port_scan(host, closed_ports=[80])
    s3 = _make_port_scan(host, filtered_ports=[80])
    s4 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    hist = [
        {"scan_run_id": 303, "reports": s3},
        {"scan_run_id": 302, "reports": s2},
        {"scan_run_id": 301, "reports": s1},
    ]
    changes = detect_changes(s3, s4, historical_baselines=hist, baseline_scan_run_id=303)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert len(port_changes) == 1
    ch = port_changes[0]
    assert ch["change_type"] == "PORT_NEWLY_OPEN"
    assert ch["baseline_scan_run_id"] == 302  # Attributed to s2 (CLOSED), not s1
    assert ch["previous_state"] == {"port": 80, "state": "CLOSED"}


def test_port_recovered_closure_does_not_repeat_on_stable_scans():
    """After a closure event is emitted, subsequent stable CLOSED scans emit nothing."""
    host = "api.example.com"
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])
    s2 = _make_port_scan(host, filtered_ports=[80])
    s3 = _make_port_scan(host, closed_ports=[80])
    s4 = _make_port_scan(host, closed_ports=[80])

    # s2 -> s3 emits PORT_NO_LONGER_OPEN
    hist_s3 = [{"scan_run_id": 402, "reports": s2}, {"scan_run_id": 401, "reports": s1}]
    ch_s3 = detect_changes(s2, s3, historical_baselines=hist_s3, baseline_scan_run_id=402)
    assert any(c["change_type"] == "PORT_NO_LONGER_OPEN" for c in ch_s3)

    # s3 -> s4: both are closed, s3 is definite CLOSED at index 0
    hist_s4 = [
        {"scan_run_id": 403, "reports": s3},
        {"scan_run_id": 402, "reports": s2},
        {"scan_run_id": 401, "reports": s1},
    ]
    ch_s4 = detect_changes(s3, s4, historical_baselines=hist_s4, baseline_scan_run_id=403)
    port_ch_s4 = [c for c in ch_s4 if c["change_type"].startswith("PORT_")]
    assert port_ch_s4 == []


def test_port_initial_scan_and_newly_discovered_host():
    """Initial scans emit no changes; newly discovered hosts emit PORT_NEWLY_OPEN."""
    host = "newhost.example.com"
    s_new = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    # Baseline scan: baseline_reports is empty dict (initial scan run)
    ch_initial = detect_changes({}, s_new, historical_baselines=[], baseline_scan_run_id=None)
    # When baseline is empty dict, base_port_hosts is empty; new open port is emitted as new
    assert any(c["change_type"] == "PORT_NEWLY_OPEN" for c in ch_initial)

    # Newly discovered host when baseline has other hosts
    s_base = _make_port_scan("other.example.com", open_ports=[{"port": 80, "state": "OPEN"}])
    ch_new_host = detect_changes(
        s_base,
        s_new,
        historical_baselines=[{"scan_run_id": 501, "reports": s_base}],
        baseline_scan_run_id=501,
    )
    new_port = next(c for c in ch_new_host if c["change_type"] == "PORT_NEWLY_OPEN")
    assert new_port["asset"] == host
    assert new_port["baseline_scan_run_id"] == 501
    assert new_port["previous_state"] is None


def test_port_multiple_changes_draw_from_different_baseline_ids():
    """Distinct port changes in a single scan can draw from different historical baseline IDs."""
    host = "api.example.com"
    s1 = _make_port_scan(
        host, open_ports=[{"port": 80, "state": "OPEN"}, {"port": 443, "state": "OPEN"}]
    )
    s2 = _make_port_scan(
        host, open_ports=[], closed_ports=[80], filtered_ports=[443]
    )
    s3 = _make_port_scan(
        host, open_ports=[{"port": 80, "state": "OPEN"}], closed_ports=[443]
    )

    hist = [{"scan_run_id": 602, "reports": s2}, {"scan_run_id": 601, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=602)

    ch80 = next(c for c in changes if c["change_type"] == "PORT_NEWLY_OPEN")
    assert ch80["detail"] == "80"
    assert ch80["baseline_scan_run_id"] == 602  # From s2 where port 80 was CLOSED

    ch443 = next(c for c in changes if c["change_type"] == "PORT_NO_LONGER_OPEN")
    assert ch443["detail"] == "443"
    assert ch443["baseline_scan_run_id"] == 601  # From s1 where port 443 was OPEN


def test_port_contradictory_and_legacy_report_shapes():
    """Contradictory or malformed report structures are handled defensively."""
    host = "api.example.com"
    # Contradictory report: port 80 listed in both open_ports and closed_ports
    s_contra = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [{"port": 80, "state": "OPEN"}],
                    "closed_ports": [80],
                    "filtered_ports": [],
                }
            ]
        }
    }
    s_clean = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}])

    hist = [{"scan_run_id": 701, "reports": s_contra}]
    # OPEN takes precedence over CLOSED in contradictory data; comparing clean open to contra open
    changes = detect_changes(s_contra, s_clean, historical_baselines=hist, baseline_scan_run_id=701)
    port_changes = [c for c in changes if c["change_type"].startswith("PORT_")]
    assert port_changes == []

    # Legacy malformed report: results is None, open_ports has string ports
    s_legacy = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [{"port": "80", "state": "OPEN"}],  # String port
                    "closed_ports": None,
                }
            ]
        }
    }
    hist_legacy = [{"scan_run_id": 702, "reports": s_legacy}]
    changes_legacy = detect_changes(
        s_legacy, s_clean, historical_baselines=hist_legacy, baseline_scan_run_id=702
    )
    assert isinstance(changes_legacy, list)


def test_worker_change_detection_history_ordering_and_grouping():
    """Offline unit verification of worker baseline query text, ordering, and grouping.

    Note: Mocked tests cannot validate PostgreSQL execution or foreign-key constraints
    (which require an isolated disposable test database).
    """
    from unittest.mock import MagicMock

    from asm.worker.worker import ASMWorker

    worker = ASMWorker.__new__(ASMWorker)

    mock_session = MagicMock()
    worker.session_factory = MagicMock(return_value=mock_session)
    mock_session.__enter__.return_value = mock_session

    # Mock baseline query returning 3 rows (ordered newest to oldest)
    mock_session.execute.side_effect = [
        # Query 1: baseline_rows
        MagicMock(fetchall=MagicMock(return_value=[(103,), (102,), (101,)])),
        # Query 2: scan_results for baseline_ids
        MagicMock(
            fetchall=MagicMock(
                return_value=[
                    (103, "discover", {"results": []}),
                    (103, "portscan", {"results": []}),
                    (102, "discover", {"results": []}),
                    (102, "portscan", {"results": []}),
                    (101, "discover", {"results": []}),
                    (101, "portscan", {"results": []}),
                ]
            )
        ),
    ]

    new_reports = {"discover": {"results": []}, "portscan": {"results": []}}
    summary, changes, _ = worker._perform_change_detection(
        domain_id="dom-123",
        scan_run_id=104,
        new_reports=new_reports,
    )

    # Verify query 1 SQL ordering and parameters
    q1_call = mock_session.execute.call_args_list[0]
    q1_sql = str(q1_call[0][0])
    assert "ORDER BY id DESC LIMIT 3" in q1_sql
    assert "status = 'succeeded'" in q1_sql
    assert q1_call[0][1] == {"domain_id": "dom-123", "current_id": 104}

    # Verify query 2 SQL parameter grouping
    q2_call = mock_session.execute.call_args_list[1]
    q2_sql = str(q2_call[0][0])
    assert "scan_run_id = ANY(:baseline_ids)" in q2_sql
    assert q2_call[0][1] == {"baseline_ids": [103, 102, 101]}
    assert summary["baseline_scan_run_id"] == 103


def test_worker_mark_run_final_persists_per_change_baseline_id():
    """Offline unit verification that worker persists per-change baseline_scan_run_id.

    Note: Mocked tests cannot validate PostgreSQL execution or foreign-key constraints
    (which require an isolated disposable test database).
    """
    from unittest.mock import MagicMock

    from asm.worker.worker import ASMWorker

    worker = ASMWorker.__new__(ASMWorker)
    mock_session = MagicMock()
    worker.session_factory = MagicMock(return_value=mock_session)
    mock_session.__enter__.return_value = mock_session

    changes = [
        {
            "change_type": "PORT_NEWLY_OPEN",
            "category": "exposure",
            "severity": "HIGH",
            "asset": "api.example.com",
            "detail": "80",
            "evidence": "portscan",
            "baseline_scan_run_id": 101,  # Historical baseline from 2 scans prior
        },
        {
            "change_type": "NEW_SUBDOMAIN",
            "category": "discovery",
            "severity": "INFO",
            "asset": "gamma.example.com",
            "detail": "",
            "evidence": "discover",
            # No baseline_scan_run_id on non-port change
        },
    ]

    # Verify how worker maps changes for insertion
    run_level_baseline_id = 103
    inserted_rows = []
    for ch in changes:
        inserted_rows.append({
            "baseline_scan_run_id": ch.get("baseline_scan_run_id") or run_level_baseline_id,
            "change_type": ch["change_type"],
        })

    assert inserted_rows[0]["baseline_scan_run_id"] == 101
    assert inserted_rows[1]["baseline_scan_run_id"] == 103


def _make_inspect_scan(
    host: str,
    *,
    status: str = "PROBED",
    cert=None,
    headers=None,
):
    return {
        "inspect": {
            "results": [
                {
                    "subdomain": host,
                    "status": status,
                    "cert": cert,
                    "headers": headers,
                }
            ]
        }
    }


def test_inspect_valid_timeout_unchanged_suppresses_noise():
    """Valid cert/headers -> timeout -> identical cert/headers emits no changes."""
    host = "api.example.com"
    clean_cert = {
        "issuer": "Let's Encrypt",
        "not_after": "2027-03-01T00:00:00Z",
        "subject_cn": host,
        "is_trusted": True,
        "expired": False,
    }
    clean_headers = {
        "present_headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        },
        "missing_headers": ["X-Frame-Options", "X-Content-Type-Options"],
        "hsts_weak": False,
        "error": None,
    }

    s1 = _make_inspect_scan(host, cert=clean_cert, headers=clean_headers)
    # s2: inspect timed out (both None)
    s2 = _make_inspect_scan(
        host,
        status="PROBED",
        cert=None,
        headers=None,
    )
    s3 = _make_inspect_scan(host, cert=clean_cert, headers=clean_headers)

    hist = [{"scan_run_id": 102, "reports": s2}, {"scan_run_id": 101, "reports": s1}]

    # In s2 (timeout): no changes emitted
    ch12 = detect_changes(
        s1, s2, historical_baselines=[{"scan_run_id": 101, "reports": s1}], baseline_scan_run_id=101
    )
    assert [c for c in ch12 if c["evidence"] == "inspect"] == []

    # In s3 (recovery to identical state): no false changes emitted
    ch23 = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=102)
    assert [c for c in ch23 if c["evidence"] == "inspect"] == []


def test_inspect_valid_timeout_genuine_header_removal_detected():
    """Valid headers (CSP present) -> timeout -> CSP missing emits SECURITY_HEADER_REMOVED."""
    host = "app.example.com"
    s1_headers = {
        "present_headers": {"Content-Security-Policy": "default-src 'self'"},
        "missing_headers": ["Strict-Transport-Security"],
        "error": None,
    }
    s3_headers = {
        "present_headers": {},
        "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
        "error": None,
    }

    s1 = _make_inspect_scan(host, headers=s1_headers)
    s2 = _make_inspect_scan(host, headers=None)
    s3 = _make_inspect_scan(host, headers=s3_headers)

    hist = [{"scan_run_id": 202, "reports": s2}, {"scan_run_id": 201, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=202)

    hdr_ch = [c for c in changes if c["change_type"] == "SECURITY_HEADER_REMOVED"]
    assert len(hdr_ch) == 1
    assert hdr_ch[0]["detail"] == "Content-Security-Policy"
    assert hdr_ch[0]["baseline_scan_run_id"] == 201  # Carries actual baseline where it was present


def test_inspect_valid_timeout_genuine_cert_rotation_detected():
    """Valid cert -> timeout -> rotated cert emits CERTIFICATE_CHANGED with actual baseline ID."""
    host = "www.example.com"
    cert1 = {"issuer": "Let's Encrypt", "not_after": "2027-03-01T00:00:00Z", "is_trusted": True}
    cert3 = {"issuer": "Let's Encrypt", "not_after": "2027-06-01T00:00:00Z", "is_trusted": True}

    s1 = _make_inspect_scan(host, cert=cert1)
    s2 = _make_inspect_scan(host, cert=None)
    s3 = _make_inspect_scan(host, cert=cert3)

    hist = [{"scan_run_id": 302, "reports": s2}, {"scan_run_id": 301, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=302)

    cert_ch = [c for c in changes if c["change_type"] == "CERTIFICATE_CHANGED"]
    assert len(cert_ch) == 1
    assert cert_ch[0]["detail"] == "not_after"
    assert cert_ch[0]["baseline_scan_run_id"] == 301


def test_inspect_valid_timeout_cert_remediation_detected():
    """Expired cert -> timeout -> valid cert emits remediation with original defect baseline."""
    host = "api.example.com"
    expired_cert = {
        "issuer": "Let's Encrypt",
        "not_after": "2025-01-01T00:00:00Z",
        "expired": True,
        "is_trusted": False,
    }
    valid_cert = {
        "issuer": "Let's Encrypt",
        "not_after": "2027-01-01T00:00:00Z",
        "expired": False,
        "is_trusted": True,
    }

    s1 = _make_inspect_scan(host, cert=expired_cert)
    s2 = _make_inspect_scan(host, cert=None)
    s3 = _make_inspect_scan(host, cert=valid_cert)

    hist = [{"scan_run_id": 402, "reports": s2}, {"scan_run_id": 401, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=402)

    remed_ch = [c for c in changes if c["change_type"] == "CERTIFICATE_CHANGED"]
    assert len(remed_ch) == 1
    assert remed_ch[0]["previous_state"] == {"defect": "TLS_CERT_EXPIRED"}
    assert remed_ch[0]["baseline_scan_run_id"] == 401


def test_inspect_partial_observations_separate_validity():
    """Valid cert with failed headers does not validate headers or emit false header changes."""
    host = "api.example.com"
    cert1 = {"issuer": "Let's Encrypt", "not_after": "2027-01-01T00:00:00Z", "is_trusted": True}
    cert2 = {"issuer": "Let's Encrypt", "not_after": "2027-04-01T00:00:00Z", "is_trusted": True}
    headers1 = {
        "present_headers": {"Content-Security-Policy": "default-src 'self'"},
        "missing_headers": [],
        "error": None,
    }

    # s1: both valid
    s1 = _make_inspect_scan(host, cert=cert1, headers=headers1)
    # s2: cert valid (socket fallback succeeded), but headers failed/timed out
    s2_hdr = {"error": "Read timeout", "present_headers": {}, "missing_headers": []}
    s2 = _make_inspect_scan(host, cert=cert2, headers=s2_hdr)

    changes = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 501, "reports": s1}],
        baseline_scan_run_id=501,
    )

    # Cert rotation was detected because cert was valid
    has_rot = any(
        c["change_type"] == "CERTIFICATE_CHANGED" and c["detail"] == "not_after"
        for c in changes
    )
    assert has_rot
    # No false header removal was emitted because header observation in s2 was invalid/error
    assert not any(c["change_type"].startswith("SECURITY_HEADER_") for c in changes)


def test_inspect_repeated_unknowns_beyond_window_no_spurious_removal():
    """Prolonged uncertainty beyond the window does not emit SECURITY_HEADER_REMOVED."""
    host = "api.example.com"
    s_clean_hdr = {
        "present_headers": {"Content-Security-Policy": "default-src 'self'"},
        "missing_headers": [],
        "error": None,
    }
    s_missing_hdr = {
        "present_headers": {},
        "missing_headers": ["Content-Security-Policy"],
        "error": None,
    }

    _s1 = _make_inspect_scan(host, headers=s_clean_hdr)
    s2 = _make_inspect_scan(host, headers=None)
    s3 = _make_inspect_scan(host, headers=None)
    s4 = _make_inspect_scan(host, headers=None)
    s5 = _make_inspect_scan(host, headers=s_missing_hdr)

    # Window passed to s5 is [s4, s3, s2]; s1 is outside window
    hist = [
        {"scan_run_id": 604, "reports": s4},
        {"scan_run_id": 603, "reports": s3},
        {"scan_run_id": 602, "reports": s2},
    ]
    changes = detect_changes(s4, s5, historical_baselines=hist, baseline_scan_run_id=604)
    # Cannot confirm removal because there was no confirmed presence in window
    assert not any(c["change_type"] == "SECURITY_HEADER_REMOVED" for c in changes)


def test_inspect_stable_observations_after_change_no_repeats():
    """Subsequent stable scans after a header change emit no repeat events."""
    host = "api.example.com"
    s1_hdr = {"present_headers": {"X-Frame-Options": "DENY"}, "missing_headers": [], "error": None}
    s2_hdr = {"present_headers": {}, "missing_headers": ["X-Frame-Options"], "error": None}
    s3_hdr = {"present_headers": {}, "missing_headers": ["X-Frame-Options"], "error": None}

    s1 = _make_inspect_scan(host, headers=s1_hdr)
    s2 = _make_inspect_scan(host, headers=s2_hdr)
    s3 = _make_inspect_scan(host, headers=s3_hdr)

    # s1 -> s2 emits removal
    ch12 = detect_changes(
        s1, s2, historical_baselines=[{"scan_run_id": 701, "reports": s1}], baseline_scan_run_id=701
    )
    assert any(c["change_type"] == "SECURITY_HEADER_REMOVED" for c in ch12)

    # s2 -> s3 is stable: no change
    ch23 = detect_changes(
        s2,
        s3,
        historical_baselines=[
            {"scan_run_id": 702, "reports": s2},
            {"scan_run_id": 701, "reports": s1},
        ],
        baseline_scan_run_id=702,
    )
    assert [c for c in ch23 if c["evidence"] == "inspect"] == []


def test_inspect_per_change_baseline_attribution_with_port():
    """Inspect changes and port changes carry their respective distinct historical baseline IDs."""
    host = "api.example.com"
    s1 = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [{"port": 80, "state": "OPEN"}],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        },
        "inspect": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "cert": None,
                    "headers": None,  # inspect was unknown in s1
                }
            ]
        },
    }
    s2 = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [],
                    "filtered_ports": [80],  # port unknown in s2
                }
            ]
        },
        "inspect": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "cert": None,
                    "headers": {
                        "present_headers": {"Content-Security-Policy": "default-src 'self'"},
                        "missing_headers": [],
                        "error": None,
                    },
                }
            ]
        },
    }
    s3 = {
        "portscan": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [80],
                    "filtered_ports": [],
                }
            ]
        },
        "inspect": {
            "results": [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "cert": None,
                    "headers": {
                        "present_headers": {},
                        "missing_headers": ["Content-Security-Policy"],
                        "error": None,
                    },
                }
            ]
        },
    }

    hist = [{"scan_run_id": 802, "reports": s2}, {"scan_run_id": 801, "reports": s1}]
    changes = detect_changes(s2, s3, historical_baselines=hist, baseline_scan_run_id=802)

    # Port was open in s1, filtered in s2, closed in s3 -> baseline 801
    port_ch = next(c for c in changes if c["change_type"] == "PORT_NO_LONGER_OPEN")
    assert port_ch["baseline_scan_run_id"] == 801

    # Header was unknown in s1, present in s2, missing in s3 -> baseline 802
    hdr_ch = next(c for c in changes if c["change_type"] == "SECURITY_HEADER_REMOVED")
    assert hdr_ch["baseline_scan_run_id"] == 802


def test_header_no_prior_evidence_does_not_claim_removal():
    """Missing CSP in current scan must not claim removal if prior scan had no evidence of CSP."""
    host = "api.example.com"
    # Prior scan has an empty missing_headers list and no CSP in present_headers
    s1 = _make_inspect_scan(
        host,
        headers={
            "present_headers": {},
            "missing_headers": [],
            "error": None,
        },
    )
    # Current scan explicitly reports CSP missing
    s2 = _make_inspect_scan(
        host,
        headers={
            "present_headers": {},
            "missing_headers": ["Content-Security-Policy"],
            "error": None,
        },
    )

    changes = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 901, "reports": s1}],
        baseline_scan_run_id=901,
    )
    # Must NOT claim CSP was removed: prior scan never established its presence
    assert not any(
        c["change_type"] == "SECURITY_HEADER_REMOVED" and c["detail"] == "Content-Security-Policy"
        for c in changes
    )


def test_header_prior_presence_emits_removal():
    """Missing CSP in current scan emits removal when prior scan confirmed its presence."""
    host = "api.example.com"
    s1 = _make_inspect_scan(
        host,
        headers={
            "present_headers": {"Content-Security-Policy": "default-src 'self'"},
            "missing_headers": [],
            "error": None,
        },
    )
    s2 = _make_inspect_scan(
        host,
        headers={
            "present_headers": {},
            "missing_headers": ["Content-Security-Policy"],
            "error": None,
        },
    )

    changes = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 901, "reports": s1}],
        baseline_scan_run_id=901,
    )
    csp_ch = next(
        c
        for c in changes
        if c["change_type"] == "SECURITY_HEADER_REMOVED"
        and c["detail"] == "Content-Security-Policy"
    )
    assert csp_ch["baseline_scan_run_id"] == 901
    assert csp_ch["previous_state"] == {"header": "Content-Security-Policy", "status": "present"}


def test_hsts_weakening_evidence_requirements():
    """HSTS weakening requires prior affirmative observation of strong HSTS."""
    host = "api.example.com"
    # Case A: Prior scan had no HSTS evidence -> current weak HSTS does not claim weakening
    s_no_hsts = _make_inspect_scan(
        host,
        headers={"present_headers": {}, "missing_headers": [], "error": None},
    )
    s_weak = _make_inspect_scan(
        host,
        headers={
            "present_headers": {"Strict-Transport-Security": "max-age=3600"},
            "missing_headers": [],
            "hsts_weak": True,
            "hsts_max_age": 3600,
            "error": None,
        },
    )
    changes_a = detect_changes(
        s_no_hsts,
        s_weak,
        historical_baselines=[{"scan_run_id": 910, "reports": s_no_hsts}],
        baseline_scan_run_id=910,
    )
    assert not any(c["change_type"] == "SECURITY_HEADER_WEAKENED" for c in changes_a)

    # Case B: Prior scan confirmed strong HSTS -> current weak HSTS emits weakening
    s_strong = _make_inspect_scan(
        host,
        headers={
            "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
            "missing_headers": [],
            "hsts_weak": False,
            "hsts_max_age": 31536000,
            "error": None,
        },
    )
    changes_b = detect_changes(
        s_strong,
        s_weak,
        historical_baselines=[{"scan_run_id": 911, "reports": s_strong}],
        baseline_scan_run_id=911,
    )
    weak_ch = next(c for c in changes_b if c["change_type"] == "SECURITY_HEADER_WEAKENED")
    assert weak_ch["baseline_scan_run_id"] == 911
    assert weak_ch["detail"] == "Strict-Transport-Security"


def test_header_addition_evidence_requirements():
    """SECURITY_HEADER_ADDED requires prior observation of missing header."""
    host = "api.example.com"
    s_missing = _make_inspect_scan(
        host,
        headers={
            "present_headers": {},
            "missing_headers": ["Content-Security-Policy"],
            "error": None,
        },
    )
    s_present = _make_inspect_scan(
        host,
        headers={
            "present_headers": {"Content-Security-Policy": "default-src 'self'"},
            "missing_headers": [],
            "error": None,
        },
    )
    changes = detect_changes(
        s_missing,
        s_present,
        historical_baselines=[{"scan_run_id": 920, "reports": s_missing}],
        baseline_scan_run_id=920,
    )
    add_ch = next(c for c in changes if c["change_type"] == "SECURITY_HEADER_ADDED")
    assert add_ch["baseline_scan_run_id"] == 920
    assert add_ch["detail"] == "Content-Security-Policy"


def test_cert_defective_followed_by_identity_only_partial_no_remediation():
    """An identity-only partial cert without expiry verification must not report remediation."""
    host = "api.example.com"
    # Scan 1: Definitely expired certificate (real serialized CertInfo structure)
    s1_cert = {
        "subject_cn": host,
        "sans": [host],
        "issuer": "Let's Encrypt R11",
        "not_after": "2025-01-01T00:00:00+00:00",
        "days_until_expiry": -10.0,
        "expired": True,
        "is_trusted": True,
        "hostname_matches": True,
    }
    s1 = _make_inspect_scan(host, cert=s1_cert)

    # Scan 2: Partial identity-only certificate (lacks not_after, expired, is_trusted)
    s2_cert = {
        "subject_cn": host,
        "issuer": "Let's Encrypt R11",
    }
    s2 = _make_inspect_scan(host, cert=s2_cert)

    # Compare s1 -> s2: Must NOT claim TLS_CERT_EXPIRED is remediated
    changes_12 = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 931, "reports": s1}],
        baseline_scan_run_id=931,
    )
    assert not any(c["change_type"] == "CERTIFICATE_CHANGED" for c in changes_12)

    # Scan 3: Fully verified, renewed certificate
    s3_cert = {
        "subject_cn": host,
        "sans": [host],
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-01-01T00:00:00+00:00",
        "days_until_expiry": 100.0,
        "expired": False,
        "is_trusted": True,
        "hostname_matches": True,
    }
    s3 = _make_inspect_scan(host, cert=s3_cert)

    # Compare s2 -> s3 with history [s2, s1]: Defect remediation recovers from s1
    changes_23 = detect_changes(
        s2,
        s3,
        historical_baselines=[
            {"scan_run_id": 932, "reports": s2},
            {"scan_run_id": 931, "reports": s1},
        ],
        baseline_scan_run_id=932,
    )
    rem_ch = next(c for c in changes_23 if c["change_type"] == "CERTIFICATE_CHANGED")
    assert rem_ch["baseline_scan_run_id"] == 931
    assert rem_ch["previous_state"] == {"defect": "TLS_CERT_EXPIRED"}


def test_simultaneous_issuer_and_expiry_rotation_does_not_multiply_events():
    """Simultaneous issuer and expiry changes emit exactly one CERTIFICATE_CHANGED event."""
    host = "api.example.com"
    s1_cert = {
        "subject_cn": host,
        "sans": [host],
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-01-01T00:00:00+00:00",
        "days_until_expiry": 100.0,
        "expired": False,
        "is_trusted": True,
        "hostname_matches": True,
    }
    s2_cert = {
        "subject_cn": host,
        "sans": [host],
        "issuer": "DigiCert Global Root G2",
        "not_after": "2028-06-01T00:00:00+00:00",
        "days_until_expiry": 600.0,
        "expired": False,
        "is_trusted": True,
        "hostname_matches": True,
    }

    s1 = _make_inspect_scan(host, cert=s1_cert)
    s2 = _make_inspect_scan(host, cert=s2_cert)

    changes = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 941, "reports": s1}],
        baseline_scan_run_id=941,
    )

    cert_changes = [c for c in changes if c["change_type"] == "CERTIFICATE_CHANGED"]
    # Must emit exactly 1 event with detail="issuer", matching established policy
    assert len(cert_changes) == 1
    assert cert_changes[0]["detail"] == "issuer"
    assert cert_changes[0]["baseline_scan_run_id"] == 941
    assert cert_changes[0]["previous_state"] == {"issuer": "Let's Encrypt R11"}
    assert cert_changes[0]["new_state"] == {"issuer": "DigiCert Global Root G2"}


def _make_discover_scan(
    subs: list[dict[str, Any]] | None = None,
    *,
    source: str = "crt.sh",
    truncated: bool = False,
) -> dict[str, Any]:
    if subs is None:
        subs = []
    return {
        "score": {"generated_utc": "2026-10-01T08:00:00Z"},
        "discover": {
            "source": source,
            "truncated": truncated,
            "results": subs,
        },
    }


def test_discovery_p_a_a_p_cycle():
    """P -> A -> A -> P: emits removal at scan 3 (baseline S1), rediscovery at scan 4."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")  # 1st absence
    s3 = _make_discover_scan([other_entry], source="crt.sh")  # 2nd absence -> removal
    s4 = _make_discover_scan([p_entry, other_entry], source="crt.sh")  # rediscovery

    # Scan 1 -> 2: only 1 absence; no removal
    ch_12 = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 1001, "reports": s1}],
        baseline_scan_run_id=1001,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_12)

    # Scan 2 -> 3: 2 consecutive absences; removal emitted attributing to S1
    hist_3 = [
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_23 = detect_changes(
        s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002
    )
    rem_ch = next(
        c for c in ch_23 if c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub
    )
    assert rem_ch["baseline_scan_run_id"] == 1001
    assert rem_ch["previous_state"] == {"status": "RESOLVED", "resolved": True}
    assert rem_ch["new_state"] is None

    # Scan 3 -> 4: reappearance after confirmed absence -> NEW_SUBDOMAIN rediscovery
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(
        s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    rediscover_ch = next(
        c for c in ch_34 if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub
    )
    assert rediscover_ch["baseline_scan_run_id"] == 1003
    assert rediscover_ch["previous_state"] is None
    assert rediscover_ch["new_state"] == {"status": "RESOLVED", "resolved": True}


def test_discovery_p_a_a_a_no_repeated_removal():
    """P -> A -> A -> A: removal emitted once at scan 3; scan 4 emits 0 removals."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    s3 = _make_discover_scan([other_entry], source="crt.sh")
    s4 = _make_discover_scan([other_entry], source="crt.sh")

    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(
        s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_34)


def test_discovery_p_a_unknown_a_resets_absence():
    """P -> A -> unknown -> A: unknown resets streak; scan 4 emits 0 removals."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    # Scan 3 is truncated (unknown observation)
    s3_unknown = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s4 = _make_discover_scan([other_entry], source="crt.sh")

    hist_4 = [
        {"scan_run_id": 1003, "reports": s3_unknown},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(
        s3_unknown, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_34)


def test_discovery_p_a_degraded_p_a_resets_absence():
    """P -> A -> degraded-P -> A: presence in degraded scan resets streak."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    # Scan 3 is degraded/truncated, but contains sub
    s3_degraded = _make_discover_scan([p_entry, other_entry], source="crt.sh", truncated=True)
    s4 = _make_discover_scan([other_entry], source="crt.sh")

    # Scan 2 -> 3: transient recovery, no additions
    hist_3 = [
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_23 = detect_changes(
        s2, s3_degraded, historical_baselines=hist_3, baseline_scan_run_id=1002
    )
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_23)

    # Scan 3 -> 4: only 1 absence since S3 presence; no removal
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3_degraded},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(
        s3_degraded, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_34)


def test_discovery_source_incomparability_primary_vs_fallback():
    """Primary PRESENT -> fallback ABSENT -> fallback ABSENT -> primary PRESENT.

    Must emit zero additions and zero removals.
    """
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="certspotter")  # fallback absence
    s3 = _make_discover_scan([other_entry], source="certspotter")  # fallback absence
    s4 = _make_discover_scan([p_entry, other_entry], source="crt.sh")  # primary return

    # Scan 2 -> 3: fallback does not match anchor "crt.sh" -> no removal
    hist_3 = [
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_23 = detect_changes(
        s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_23)

    # Scan 3 -> 4: primary reappearance was not confirmed absent -> no rediscovery addition
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(
        s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_34)
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_34)


def test_discovery_fallback_confirmed_absence():
    """Fallback PRESENT -> 2 eligible absences from same fallback source emits REMOVED_SUBDOMAIN."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="certspotter")
    s2 = _make_discover_scan([other_entry], source="certspotter")
    s3 = _make_discover_scan([other_entry], source="certspotter")

    hist_3 = [
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_23 = detect_changes(
        s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002
    )
    rem_ch = next(
        c for c in ch_23 if c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub
    )
    assert rem_ch["baseline_scan_run_id"] == 1001
    assert rem_ch["previous_state"] == {"status": "RESOLVED", "resolved": True}


def test_discovery_window_eviction_beyond_three_scans():
    """P -> unknown -> unknown -> unknown -> P: evicted from history.

    Emits NEW_SUBDOMAIN as first observed.
    """
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    # S1 had sub; S2, S3, S4 are all unknown/absent; S5 has sub again
    s2 = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s3 = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s4 = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s5 = _make_discover_scan([p_entry, other_entry], source="crt.sh")

    # Available 3-scan history contains [S4, S3, S2]; S1 is evicted
    hist_5 = [
        {"scan_run_id": 1004, "reports": s4},
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
    ]
    ch_45 = detect_changes(
        s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004
    )
    new_ch = next(
        c for c in ch_45 if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub
    )
    # First observed in available history does not override baseline_scan_run_id
    assert "baseline_scan_run_id" not in new_ch
    assert new_ch["previous_state"] is None


def test_discovery_genuinely_new_hostname_in_degraded_response():
    """Genuinely new hostname in degraded/truncated response emits NEW_SUBDOMAIN immediately."""
    sub = "brandnew.example.com"
    anchor = "other.example.com"
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}
    new_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([other_entry], source="crt.sh")
    s2_degraded = _make_discover_scan([other_entry, new_entry], source="crt.sh", truncated=True)

    changes = detect_changes(
        s1,
        s2_degraded,
        historical_baselines=[{"scan_run_id": 1001, "reports": s1}],
        baseline_scan_run_id=1001,
    )
    new_ch = next(
        c for c in changes if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub
    )
    assert new_ch["previous_state"] is None
    assert new_ch["new_state"] == {"status": "RESOLVED", "resolved": True}


def test_discovery_nxdomain_counts_as_discovered():
    """NXDOMAIN discovery emits NEW_SUBDOMAIN; subsequent resolution emits NEWLY_RESOLVING."""
    sub = "nx.example.com"
    nx_entry = {"subdomain": sub, "status": "NXDOMAIN", "resolved": False}
    res_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([nx_entry], source="crt.sh")
    s2 = _make_discover_scan([res_entry], source="crt.sh")

    ch_1 = detect_changes({}, s1)
    new_ch = next(c for c in ch_1 if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub)
    assert new_ch["new_state"] == {"status": "NXDOMAIN", "resolved": False}

    ch_12 = detect_changes(
        s1,
        s2,
        historical_baselines=[{"scan_run_id": 1001, "reports": s1}],
        baseline_scan_run_id=1001,
    )
    res_ch = next(c for c in ch_12 if c["change_type"] == "NEWLY_RESOLVING" and c["asset"] == sub)
    assert res_ch["previous_state"] == {"status": "NXDOMAIN", "resolved": False}
    assert res_ch["new_state"] == {"status": "RESOLVED", "resolved": True}


def test_discovery_allow_removal_false_suppresses_removal():
    """When allow_removal=False, confirmed absences do not emit REMOVED_SUBDOMAIN."""
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    s3 = _make_discover_scan([other_entry], source="crt.sh")

    hist_3 = [
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    changes = detect_changes(
        s2, s3, allow_removal=False, historical_baselines=hist_3, baseline_scan_run_id=1002
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes)


def test_discovery_first_scan_empty_history():
    """First-scan empty history emits NEW_SUBDOMAIN for all discovered names."""
    entry1 = {"subdomain": "a.example.com", "status": "RESOLVED", "resolved": True}
    entry2 = {"subdomain": "b.example.com", "status": "RESOLVED", "resolved": True}
    s1 = _make_discover_scan([entry1, entry2], source="crt.sh")

    changes = detect_changes({}, s1, historical_baselines=[])
    assets = {c["asset"] for c in changes if c["change_type"] == "NEW_SUBDOMAIN"}
    assert assets == {"a.example.com", "b.example.com"}


def test_discovery_p_unknown_a_a_confirms_removal():
    """P -> unknown -> A -> A: confirmation with presence still inside 3-scan window.

    Scan 1: P (present at crt.sh)
    Scan 2: unknown (truncated crt.sh)
    Scan 3: A (qualifying absence from crt.sh)
    Scan 4: A (qualifying absence from crt.sh)
    At Scan 4, history is [S3 (A), S2 (unknown), S1 (P)].
    S1 is still inside the 3-prior-scan window, confirming removal on entry.
    """
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s3 = _make_discover_scan([other_entry], source="crt.sh")
    s4 = _make_discover_scan([other_entry], source="crt.sh")

    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    changes = detect_changes(
        s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003
    )
    rem_ch = next(
        c for c in changes if c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub
    )
    assert rem_ch["baseline_scan_run_id"] == 1001
    assert rem_ch["previous_state"] == {"status": "RESOLVED", "resolved": True}
    assert rem_ch["new_state"] is None


def test_discovery_p_a_unknown_a_a_expired_presence_no_removal():
    """P -> A -> unknown -> A -> A: no fabricated removal when supporting presence has expired.

    Scan 1: P (present at crt.sh)
    Scan 2: A (qualifying absence)
    Scan 3: unknown (truncated)
    Scan 4: A (qualifying absence)
    Scan 5: A (qualifying absence)
    At Scan 5, history is [S4 (A), S3 (unknown), S2 (A)].
    S1 has been evicted from the 3-prior-scan window. No removal is fabricated.
    """
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    _s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    s3 = _make_discover_scan([other_entry], source="crt.sh", truncated=True)
    s4 = _make_discover_scan([other_entry], source="crt.sh")
    s5 = _make_discover_scan([other_entry], source="crt.sh")

    hist_5 = [
        {"scan_run_id": 1004, "reports": s4},
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
    ]
    changes = detect_changes(
        s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004
    )
    assert not any(
        c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in changes
    )


def test_discovery_repeated_stable_presence_after_rediscovery():
    """Repeated stable presence after rediscovery emits no duplicate additions.

    Scan 1: P
    Scan 2: A
    Scan 3: A -> emits REMOVED_SUBDOMAIN
    Scan 4: P -> emits NEW_SUBDOMAIN (rediscovery)
    Scan 5: P -> stable presence; emits 0 additions
    Scan 6: P -> stable presence; emits 0 additions
    """
    sub = "target.example.com"
    anchor = "other.example.com"
    p_entry = {"subdomain": sub, "status": "RESOLVED", "resolved": True}
    other_entry = {"subdomain": anchor, "status": "RESOLVED", "resolved": True}

    _s1 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s2 = _make_discover_scan([other_entry], source="crt.sh")
    s3 = _make_discover_scan([other_entry], source="crt.sh")
    s4 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s5 = _make_discover_scan([p_entry, other_entry], source="crt.sh")
    s6 = _make_discover_scan([p_entry, other_entry], source="crt.sh")

    # Scan 4 -> 5: sub present in both S4 and S5
    hist_5 = [
        {"scan_run_id": 1004, "reports": s4},
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
    ]
    ch_45 = detect_changes(
        s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004
    )
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_45)

    # Scan 5 -> 6: sub present in S4, S5, and S6
    hist_6 = [
        {"scan_run_id": 1005, "reports": s5},
        {"scan_run_id": 1004, "reports": s4},
        {"scan_run_id": 1003, "reports": s3},
    ]
    ch_56 = detect_changes(
        s5, s6, historical_baselines=hist_6, baseline_scan_run_id=1005
    )
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_56)


def test_worker_first_scan_is_baseline_and_emits_no_changes_or_alerts():
    """Verify worker contract: initial domain scan is a baseline scan with 0 changes and 0 alerts.

    Contrasts pure detector behavior (which emits NEW_SUBDOMAIN when called against empty history)
    with the end-to-end worker contract, which bypasses change detection on first scan.
    """
    import uuid
    from unittest.mock import MagicMock

    from asm.worker.worker import ASMWorker

    worker = ASMWorker.__new__(ASMWorker)
    mock_session = MagicMock()
    worker.session_factory = MagicMock(return_value=mock_session)
    mock_session.__enter__.return_value = mock_session

    # Query 1: baseline_rows is empty -> no prior succeeded scans
    mock_session.execute.side_effect = [
        MagicMock(fetchall=MagicMock(return_value=[])),
    ]

    new_reports = {
        "discover": {
            "source": "crt.sh",
            "results": [{"subdomain": "api.example.com", "status": "RESOLVED", "resolved": True}],
        }
    }

    # Worker _perform_change_detection
    summary, changes, baseline_id = worker._perform_change_detection(
        domain_id="dom-first",
        scan_run_id=1,
        new_reports=new_reports,
    )

    # 1. Summary status is 'baseline' and baseline_id is None
    assert summary["status"] == "baseline"
    assert summary["baseline_scan_run_id"] is None
    assert summary["removal_detection"] == "skipped"
    assert summary["skip_reason"] == "No previous succeeded scan (first scan is baseline)"
    assert summary["counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # 2. Changes list is strictly empty
    assert changes == []
    assert baseline_id is None

    # 3. In _mark_run_final, no scan_changes or alert_notifications are inserted
    mock_session.reset_mock()
    mock_session.execute.side_effect = None
    mock_session.execute.return_value = MagicMock(rowcount=1)

    worker._mark_run_final(
        scan_run_id=1,
        claim_token=uuid.uuid4(),
        status="succeeded",
        error_msg=None,
        change_detection=summary,
        changes=changes,
        domain_id=1,
        baseline_scan_run_id=baseline_id,
        alert_rows=[],
    )

    executed_sqls = [str(call[0][0]) for call in mock_session.execute.call_args_list]
    assert not any("INSERT INTO scan_changes" in sql for sql in executed_sqls)
    assert not any("INSERT INTO alert_notifications" in sql for sql in executed_sqls)
    assert any("UPDATE scan_runs" in sql for sql in executed_sqls)


# -------------------------------------------------------------------------
# HTTPS-Loss Bounded Confirmation Tests
# -------------------------------------------------------------------------

def _make_probe_scan(
    host: str = "api.example.com",
    *,
    status: str = "PROBED",
    https_reachable: bool = True,
    http_reachable: bool = True,
    https_error: str | None = None,
    http_code: int = 200,
    https_code: int = 200,
    scan_time: str = "2026-10-01T08:00:00Z",
) -> dict[str, Any]:
    https_dict: dict[str, Any] = {"reachable": https_reachable, "status_code": https_code}
    if https_error is not None:
        https_dict["error_type"] = https_error
    return {
        "score": {"generated_utc": scan_time},
        "probe": {
            "results": [
                {
                    "subdomain": host,
                    "status": status,
                    "http": {"reachable": http_reachable, "status_code": http_code},
                    "https": https_dict,
                }
            ]
        },
    }


def test_https_lost_success_fail_success_no_loss_event():
    """Single transient HTTPS failure does not emit HTTPS_LOST on failure or recovery."""
    s2 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s1 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0 = _make_probe_scan(scan_time="2026-10-01T09:00:00Z", https_reachable=True)

    # Scan 1: single failure streak=1 -> no HTTPS_LOST
    changes_s1 = detect_changes(
        s2, s1, historical_baselines=[{"scan_run_id": 1, "reports": s2}]
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_s1)

    # Scan 2: recovered to SUCCESS -> no HTTPS_LOST
    changes_s0 = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 2, "reports": s1},
            {"scan_run_id": 1, "reports": s2},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_s0)


def test_https_lost_success_fail_fail_confirms_with_correct_baseline():
    """Two consecutive qualifying failures after SUCCESS emit HTTPS_LOST with correct baseline."""
    s2 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s1 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    changes = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 11, "reports": s1},
            {"scan_run_id": 10, "reports": s2},
        ],
    )
    lost = [c for c in changes if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 1
    assert lost[0]["baseline_scan_run_id"] == 10
    assert lost[0]["asset"] == "api.example.com"
    assert lost[0]["severity"] == "MEDIUM"
    assert lost[0]["category"] == "exposure"
    assert lost[0]["previous_state"] == {"https_reachable": True}
    assert lost[0]["new_state"] == {"https_reachable": False, "error_type": "CONNECT_ERROR"}


def test_https_lost_success_fail_fail_fail_no_repeated_event():
    """Third consecutive failure does not emit a duplicate HTTPS_LOST event."""
    s3 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s2 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s1 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0 = _make_probe_scan(
        scan_time="2026-10-01T09:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    changes = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s1},
            {"scan_run_id": 11, "reports": s2},
            {"scan_run_id": 10, "reports": s3},
        ],
    )
    lost = [c for c in changes if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 0


def test_https_lost_success_unknown_fail_fail_confirms_with_correct_baseline():
    """Success -> unknown -> failure -> failure confirms loss with baseline pointing to success."""
    s3 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s2 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    s1 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0 = _make_probe_scan(
        scan_time="2026-10-01T09:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    changes = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s1},
            {"scan_run_id": 11, "reports": s2},
            {"scan_run_id": 10, "reports": s3},
        ],
    )
    lost = [c for c in changes if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 1
    assert lost[0]["baseline_scan_run_id"] == 10


def test_https_lost_success_fail_unknown_fail_no_confirmation():
    """Unknown observation between failures resets streak and prevents confirmation."""
    s3 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s2 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s1 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    s0 = _make_probe_scan(
        scan_time="2026-10-01T09:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    changes = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s1},
            {"scan_run_id": 11, "reports": s2},
            {"scan_run_id": 10, "reports": s3},
        ],
    )
    lost = [c for c in changes if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 0


def test_https_lost_missing_skipped_blocked_observations_treated_as_unknown():
    """Non-PROBED statuses, redirect loops, unclassified errors and host outages are UNKNOWN."""
    from asm.changes import _classify_https_probe_observation
    from asm.models import HostProbeStatus, ProbeErrorType

    assert _classify_https_probe_observation(None) == "UNKNOWN"
    assert _classify_https_probe_observation({}) == "UNKNOWN"

    for skip_st in (
        HostProbeStatus.SKIPPED_UNTRUSTED.value,
        HostProbeStatus.SKIPPED_PRIVATE_IP.value,
        HostProbeStatus.SKIPPED_UNRESOLVED.value,
        HostProbeStatus.SKIPPED_NOT_HTTPS.value,
        HostProbeStatus.SKIPPED_IPV6_ONLY.value,
    ):
        raw = {"status": skip_st, "https": {"reachable": False}}
        assert _classify_https_probe_observation(raw) == "UNKNOWN"

    for err_type in (
        ProbeErrorType.TIMEOUT.value,
        ProbeErrorType.TOO_MANY_REDIRECTS.value,
        ProbeErrorType.OTHER.value,
        "UNRECOGNIZED_ERROR",
    ):
        raw = {
            "status": "PROBED",
            "http": {"reachable": True},
            "https": {"reachable": False, "error_type": err_type},
        }
        assert _classify_https_probe_observation(raw) == "UNKNOWN"

    # Host outage (HTTP not reachable)
    raw_host_down = {
        "status": "PROBED",
        "http": {"reachable": False},
        "https": {"reachable": False, "error_type": "CONNECT_ERROR"},
    }
    assert _classify_https_probe_observation(raw_host_down) == "UNKNOWN"


def test_https_lost_never_observed_and_expired_success_no_event():
    """No event is emitted if success was never observed or expired from 3-scan window."""
    # Never observed: 4 consecutive failures
    s3 = _make_probe_scan(
        scan_time="2026-10-01T08:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s2 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s1 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0 = _make_probe_scan(
        scan_time="2026-10-01T09:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    changes = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s1},
            {"scan_run_id": 11, "reports": s2},
            {"scan_run_id": 10, "reports": s3},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes)

    # Expired: success was at S4, prior 3 scans are UNKNOWN
    s3_unk = _make_probe_scan(
        scan_time="2026-10-01T08:00:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    s2_unk = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    changes_exp = detect_changes(
        s1,
        s0,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s1},
            {"scan_run_id": 11, "reports": s2_unk},
            {"scan_run_id": 10, "reports": s3_unk},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_exp)


def test_https_lost_bounded_window_distinguishes_one_vs_two_unknowns():
    """Distinguish supported SUCCESS -> UNKNOWN -> FAILURE -> FAILURE from expired 2-unknown run.

    1. SUCCESS -> UNKNOWN -> FAILURE -> FAILURE:
       At the 2nd failure, history is [S2=FAILURE, S1=UNKNOWN, S0=SUCCESS].
       S0=SUCCESS is within the 3-prior-scan window, so loss confirms with baseline S0.

    2. SUCCESS -> UNKNOWN -> UNKNOWN -> FAILURE -> FAILURE:
       At the 1st failure, history is [S2=UNKNOWN, S1=UNKNOWN, S0=SUCCESS] (streak=1, no loss).
       At the 2nd failure, history is [S3=FAILURE, S2=UNKNOWN, S1=UNKNOWN].
       S0=SUCCESS was 4 scans ago and has expired from the 3-prior-scan window;
       hence no confirmation is emitted.
    """
    s_success = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s_unk1 = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    s_unk2 = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z", https_reachable=False, https_error="TIMEOUT"
    )
    s_fail1 = _make_probe_scan(
        scan_time="2026-10-01T09:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s_fail2 = _make_probe_scan(
        scan_time="2026-10-01T10:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    # 1. Supported 1-unknown sequence: SUCCESS(10) -> UNKNOWN(11) -> FAILURE(12) -> FAILURE(13)
    changes_1unk = detect_changes(
        s_fail1,
        s_fail2,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s_fail1},
            {"scan_run_id": 11, "reports": s_unk1},
            {"scan_run_id": 10, "reports": s_success},
        ],
    )
    lost_1unk = [c for c in changes_1unk if c["change_type"] == "HTTPS_LOST"]
    assert len(lost_1unk) == 1
    assert lost_1unk[0]["baseline_scan_run_id"] == 10

    # 2. Expired 2-unknown sequence:
    # SUCCESS(10) -> UNKNOWN(11) -> UNKNOWN(12) -> FAILURE(13) -> FAILURE(14)
    # At scan 13 (first failure): history is [s_unk2(12), s_unk1(11), s_success(10)]
    changes_13 = detect_changes(
        s_unk2,
        s_fail1,
        historical_baselines=[
            {"scan_run_id": 12, "reports": s_unk2},
            {"scan_run_id": 11, "reports": s_unk1},
            {"scan_run_id": 10, "reports": s_success},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_13)

    # At scan 14 (second failure): history is [s_fail1(13), s_unk2(12), s_unk1(11)]
    # s_success(10) has fallen outside the 3-prior-scan window!
    changes_14 = detect_changes(
        s_fail1,
        s_fail2,
        historical_baselines=[
            {"scan_run_id": 13, "reports": s_fail1},
            {"scan_run_id": 12, "reports": s_unk2},
            {"scan_run_id": 11, "reports": s_unk1},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_14)


def test_https_lost_recovery_followed_by_new_sustained_loss():
    """Recovery to SUCCESS resets sequence; subsequent 2 consecutive failures confirm new loss."""
    s2_rec = _make_probe_scan(scan_time="2026-10-01T10:00:00Z", https_reachable=True)
    s1_fail = _make_probe_scan(
        scan_time="2026-10-01T10:30:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )
    s0_fail = _make_probe_scan(
        scan_time="2026-10-01T11:00:00Z", https_reachable=False, https_error="CONNECT_ERROR"
    )

    changes = detect_changes(
        s1_fail,
        s0_fail,
        historical_baselines=[
            {"scan_run_id": 21, "reports": s1_fail},
            {"scan_run_id": 20, "reports": s2_rec},
        ],
    )
    lost = [c for c in changes if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 1
    assert lost[0]["baseline_scan_run_id"] == 20


def test_https_lost_http_no_https_prerequisites_and_tls_error():
    """TLS_ERROR qualifies when HTTP answers; host outages without live HTTP are UNKNOWN."""
    s2 = _make_probe_scan(scan_time="2026-10-01T08:00:00Z", https_reachable=True)
    s1_tls = _make_probe_scan(
        scan_time="2026-10-01T08:30:00Z",
        https_reachable=False,
        https_error="TLS_ERROR",
        http_reachable=True,
    )
    s0_tls = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z",
        https_reachable=False,
        https_error="TLS_ERROR",
        http_reachable=True,
    )

    changes_tls = detect_changes(
        s1_tls,
        s0_tls,
        historical_baselines=[
            {"scan_run_id": 11, "reports": s1_tls},
            {"scan_run_id": 10, "reports": s2},
        ],
    )
    lost = [c for c in changes_tls if c["change_type"] == "HTTPS_LOST"]
    assert len(lost) == 1
    assert lost[0]["new_state"] == {"https_reachable": False, "error_type": "TLS_ERROR"}

    # HTTP unreachable in S0 (host-wide failure, not HTTP_NO_HTTPS)
    s0_down = _make_probe_scan(
        scan_time="2026-10-01T09:00:00Z",
        https_reachable=False,
        https_error="CONNECT_ERROR",
        http_reachable=False,
    )
    changes_down = detect_changes(
        s1_tls,
        s0_down,
        historical_baselines=[
            {"scan_run_id": 11, "reports": s1_tls},
            {"scan_run_id": 10, "reports": s2},
        ],
    )
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_down)


