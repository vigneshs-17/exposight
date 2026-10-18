"""Unit tests for Exposight change detection engine (src/asm/changes.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from asm.changes import (
    bootstrap_persistent_inventory,
    detect_changes,
    evaluate_removal_eligibility,
)


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
        c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == "new.example.com" for c in changes
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
        c["change_type"] == "NEWLY_RESOLVING" and c["asset"] == "nx.example.com" for c in changes
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
    s1 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN", "service_guess": "http"}])
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
    s2 = _make_port_scan(host, open_ports=[], closed_ports=[80], filtered_ports=[443])
    s3 = _make_port_scan(host, open_ports=[{"port": 80, "state": "OPEN"}], closed_ports=[443])

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
        # Query 3: domain_subdomains inventory
        MagicMock(fetchall=MagicMock(return_value=[])),
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
        inserted_rows.append(
            {
                "baseline_scan_run_id": ch.get("baseline_scan_run_id") or run_level_baseline_id,
                "change_type": ch["change_type"],
            }
        )

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
        c["change_type"] == "CERTIFICATE_CHANGED" and c["detail"] == "not_after" for c in changes
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
    ch_23 = detect_changes(s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002)
    rem_ch = next(c for c in ch_23 if c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub)
    assert rem_ch["baseline_scan_run_id"] == 1001
    assert rem_ch["previous_state"] == {"status": "RESOLVED", "resolved": True}
    assert rem_ch["new_state"] is None

    # Scan 3 -> 4: reappearance after confirmed absence -> NEW_SUBDOMAIN rediscovery
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    ch_34 = detect_changes(s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    ch_34 = detect_changes(s3_unknown, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    ch_23 = detect_changes(s2, s3_degraded, historical_baselines=hist_3, baseline_scan_run_id=1002)
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_23)

    # Scan 3 -> 4: only 1 absence since S3 presence; no removal
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3_degraded},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(s3_degraded, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    ch_23 = detect_changes(s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002)
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in ch_23)

    # Scan 3 -> 4: primary reappearance was not confirmed absent -> no rediscovery addition
    hist_4 = [
        {"scan_run_id": 1003, "reports": s3},
        {"scan_run_id": 1002, "reports": s2},
        {"scan_run_id": 1001, "reports": s1},
    ]
    ch_34 = detect_changes(s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    ch_23 = detect_changes(s2, s3, historical_baselines=hist_3, baseline_scan_run_id=1002)
    rem_ch = next(c for c in ch_23 if c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub)
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
    ch_45 = detect_changes(s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004)
    new_ch = next(c for c in ch_45 if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub)
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
    new_ch = next(c for c in changes if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub)
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
    changes = detect_changes(s3, s4, historical_baselines=hist_4, baseline_scan_run_id=1003)
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
    changes = detect_changes(s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004)
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == sub for c in changes)


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
    ch_45 = detect_changes(s4, s5, historical_baselines=hist_5, baseline_scan_run_id=1004)
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == sub for c in ch_45)

    # Scan 5 -> 6: sub present in S4, S5, and S6
    hist_6 = [
        {"scan_run_id": 1005, "reports": s5},
        {"scan_run_id": 1004, "reports": s4},
        {"scan_run_id": 1003, "reports": s3},
    ]
    ch_56 = detect_changes(s5, s6, historical_baselines=hist_6, baseline_scan_run_id=1005)
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
    changes_s1 = detect_changes(s2, s1, historical_baselines=[{"scan_run_id": 1, "reports": s2}])
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


def test_cert_rotation_across_intervening_alternate_issuer_and_return_leg_suppression():
    """Same-issuer lookback detects rotation, suppresses identical return, flags distinct certs."""
    host = "www.example.com"
    cert_r11_old = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-03-01",
        "serial_hex": "aaa111",
        "subject_cn": host,
        "sans": [host],
        "is_trusted": True,
        "expired": False,
        "self_signed": False,
        "hostname_mismatch": False,
    }
    cert_we1 = {
        "issuer": "Google Trust Services WE1",
        "not_after": "2027-02-15",
        "serial_hex": "bbb222",
        "subject_cn": host,
        "sans": [host],
        "is_trusted": True,
        "expired": False,
        "self_signed": False,
        "hostname_mismatch": False,
    }
    cert_r11_rotated = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-06-01",
        "serial_hex": "ccc333",
        "subject_cn": host,
        "sans": [host],
        "is_trusted": True,
        "expired": False,
        "self_signed": False,
        "hostname_mismatch": False,
    }
    cert_r11_rekeyed_same_expiry = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-03-01",
        "serial_hex": "ddd444",
        "subject_cn": host,
        "sans": [host],
        "is_trusted": True,
        "expired": False,
        "self_signed": False,
        "hostname_mismatch": False,
    }

    s1 = _make_inspect_scan(host, cert=cert_r11_old)
    s2 = _make_inspect_scan(host, cert=cert_we1)
    s3_rotated = _make_inspect_scan(host, cert=cert_r11_rotated)
    s3_unchanged = _make_inspect_scan(host, cert=cert_r11_old)
    s3_rekeyed = _make_inspect_scan(host, cert=cert_r11_rekeyed_same_expiry)

    hist = [{"scan_run_id": 702, "reports": s2}, {"scan_run_id": 701, "reports": s1}]

    # Case 1: Return to R11 with rotated not_after emits detail="not_after" attributed to scan 701
    changes_rot = detect_changes(
        s2, s3_rotated, historical_baselines=hist, baseline_scan_run_id=702
    )
    cert_rot = [c for c in changes_rot if c["change_type"] == "CERTIFICATE_CHANGED"]
    assert len(cert_rot) == 1
    assert cert_rot[0]["detail"] == "not_after"
    assert cert_rot[0]["previous_state"] == {"not_after": "2027-03-01"}
    assert cert_rot[0]["new_state"] == {"not_after": "2027-06-01"}
    assert cert_rot[0]["baseline_scan_run_id"] == 701

    # Case 2: Return to identical R11 cert within bounded window emits no false issuer change
    changes_ret = detect_changes(
        s2, s3_unchanged, historical_baselines=hist, baseline_scan_run_id=702
    )
    assert not any(c["change_type"] == "CERTIFICATE_CHANGED" for c in changes_ret)

    # Case 3: Matching issuer name + matching not_after with different serial_hex is NOT identical
    changes_rekey = detect_changes(
        s2, s3_rekeyed, historical_baselines=hist, baseline_scan_run_id=702
    )
    cert_rekey = [c for c in changes_rekey if c["change_type"] == "CERTIFICATE_CHANGED"]
    assert len(cert_rekey) == 1
    assert cert_rekey[0]["detail"] == "issuer"
    assert cert_rekey[0]["previous_state"] == {"issuer": "Google Trust Services WE1"}
    assert cert_rekey[0]["new_state"] == {"issuer": "Let's Encrypt R11"}
    assert cert_rekey[0]["baseline_scan_run_id"] == 702

    # Case 4: Genuine issuer rollback after sustained switch (A -> B -> B -> B -> A)
    hist_sustained_b = [
        {"scan_run_id": 704, "reports": s2},
        {"scan_run_id": 703, "reports": s2},
        {"scan_run_id": 702, "reports": s2},
    ]
    changes_rollback = detect_changes(
        s2, s3_unchanged, historical_baselines=hist_sustained_b, baseline_scan_run_id=704
    )
    cert_rb = [c for c in changes_rollback if c["change_type"] == "CERTIFICATE_CHANGED"]
    assert len(cert_rb) == 1
    assert cert_rb[0]["detail"] == "issuer"
    assert cert_rb[0]["previous_state"] == {"issuer": "Google Trust Services WE1"}
    assert cert_rb[0]["new_state"] == {"issuer": "Let's Encrypt R11"}
    assert cert_rb[0]["baseline_scan_run_id"] == 704


def test_dns_resolution_change_across_intermediate_timeout():
    """Definite DNS lookback detects resolution transitions across intermediate TIMEOUT."""
    host = "dev.example.com"

    def _disc_scan(resolved: bool, status: str, ips: list[str]) -> dict:
        return {
            "discover": {
                "domain": "example.com",
                "scan_time": "2026-10-01T12:00:00Z",
                "results": [
                    {
                        "subdomain": host,
                        "resolved": resolved,
                        "status": status,
                        "ips": ips,
                    }
                ],
            }
        }

    s_resolved = _disc_scan(True, "RESOLVED", ["203.0.113.10"])
    s_timeout = _disc_scan(False, "TIMEOUT", [])
    s_nxdomain = _disc_scan(False, "NXDOMAIN", [])

    # 1. RESOLVED (801) -> TIMEOUT (802) -> NXDOMAIN (803) => STOPPED_RESOLVING (baseline 801)
    changes_stop = detect_changes(
        s_timeout,
        s_nxdomain,
        historical_baselines=[
            {"scan_run_id": 802, "reports": s_timeout},
            {"scan_run_id": 801, "reports": s_resolved},
        ],
        baseline_scan_run_id=802,
    )
    stopped = [c for c in changes_stop if c["change_type"] == "STOPPED_RESOLVING"]
    assert len(stopped) == 1
    assert stopped[0]["asset"] == host
    assert stopped[0]["baseline_scan_run_id"] == 801

    # 2. NXDOMAIN (801) -> TIMEOUT (802) -> RESOLVED (803) => NEWLY_RESOLVING (baseline 801)
    changes_new = detect_changes(
        s_timeout,
        s_resolved,
        historical_baselines=[
            {"scan_run_id": 802, "reports": s_timeout},
            {"scan_run_id": 801, "reports": s_nxdomain},
        ],
        baseline_scan_run_id=802,
    )
    newly = [c for c in changes_new if c["change_type"] == "NEWLY_RESOLVING"]
    assert len(newly) == 1
    assert newly[0]["asset"] == host
    assert newly[0]["baseline_scan_run_id"] == 801


def test_score_stage_stabilized_against_single_scan_noise_and_concurrent_exposure():
    """Score stage ignores 1-scan unconfirmed noise while detecting concurrent port exposures."""
    from asm.scoring import score_domain_payloads

    host = "portal.example.com"

    def _full_scan(
        *,
        https_ok: bool = True,
        open_ports: list[int] | None = None,
        filtered_ports: list[int] | None = None,
        inspect_ok: bool = True,
    ) -> dict:
        if open_ports is None:
            open_ports = [80, 443]
        if filtered_ports is None:
            filtered_ports = []
        disc = [
            {
                "subdomain": host,
                "resolved": True,
                "status": "RESOLVED",
                "ips": ["203.0.113.20"],
            }
        ]
        probe = [
            {
                "subdomain": host,
                "status": "PROBED",
                "reachable": True,
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {
                    "reachable": https_ok,
                    "status_code": 200 if https_ok else None,
                    "error_type": None if https_ok else "CONNECT_ERROR",
                },
            }
        ]
        ps = [
            {
                "subdomain": host,
                "status": "PROBED",
                "ip": "203.0.113.20",
                "open_ports": [{"port": p, "state": "OPEN", "service": "tcp"} for p in open_ports],
                "closed_ports": [],
                "filtered_ports": filtered_ports,
            }
        ]
        insp = [
            {
                "subdomain": host,
                "status": "PROBED" if https_ok else "SKIPPED",
                "cert": (
                    {
                        "issuer": "Let's Encrypt R11",
                        "not_after": "2027-03-01",
                        "is_trusted": True,
                        "expired": False,
                        "self_signed": False,
                        "hostname_mismatch": False,
                    }
                    if (https_ok and inspect_ok)
                    else None
                ),
                "headers": (
                    {
                        "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                        "missing_headers": ["Content-Security-Policy"],
                        "error": None,
                    }
                    if (https_ok and inspect_ok)
                    else None
                ),
            }
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        ts = "2026-10-01T12:00:00Z"
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    s_clean = _full_scan()
    s_probe_glitch = _full_scan(https_ok=False)

    # 1. Single-scan unconfirmed probe failure does not trigger false RISK_BAND_INCREASED
    ch_glitch = detect_changes(
        s_clean,
        s_probe_glitch,
        historical_baselines=[{"scan_run_id": 901, "reports": s_clean}],
        baseline_scan_run_id=901,
    )
    assert not any("RISK_BAND" in c["change_type"] for c in ch_glitch)

    # Recovery scan after 1-scan probe glitch does not trigger false RISK_BAND_DECREASED
    ch_rec = detect_changes(
        s_probe_glitch,
        s_clean,
        historical_baselines=[
            {"scan_run_id": 902, "reports": s_probe_glitch},
            {"scan_run_id": 901, "reports": s_clean},
        ],
        baseline_scan_run_id=902,
    )
    assert not any("RISK_BAND" in c["change_type"] for c in ch_rec)

    # 2. Concurrent genuine RDP exposure (3389) on the same scan as a 1-scan probe glitch
    s_rdp_with_probe_glitch = _full_scan(https_ok=False, open_ports=[80, 443, 3389])
    ch_concurrent = detect_changes(
        s_clean,
        s_rdp_with_probe_glitch,
        historical_baselines=[{"scan_run_id": 901, "reports": s_clean}],
        baseline_scan_run_id=901,
    )
    host_inc = [c for c in ch_concurrent if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc) == 1
    assert host_inc[0]["previous_state"]["band"] == "LOW"
    assert host_inc[0]["new_state"]["band"] == "HIGH"


def test_partial_inspection_preserves_fresh_cert_or_header_evidence_independently():
    """Fresh cert defect survives header timeout and fresh header finding survives cert timeout."""
    from asm.scoring import score_domain_payloads

    host = "api.example.com"
    ts = "2026-10-01T12:00:00Z"

    def _build_scan(
        cert_dict: dict | None,
        headers_dict: dict | None,
        ports: list[int] | None = None,
    ) -> dict:
        if ports is None:
            ports = [80, 443]
        disc = [
            {
                "subdomain": host,
                "resolved": True,
                "status": "RESOLVED",
                "ips": ["203.0.113.5"],
            }
        ]
        probe = [
            {
                "subdomain": host,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
        ]
        ps = [
            {
                "subdomain": host,
                "status": "PROBED",
                "open_ports": [{"port": p, "state": "OPEN"} for p in ports],
                "closed_ports": [],
                "filtered_ports": [],
            }
        ]
        insp = [
            {
                "subdomain": host,
                "status": "PROBED",
                "cert": cert_dict,
                "headers": headers_dict,
            }
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    clean_cert = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-03-01",
        "is_trusted": True,
        "expired": False,
    }
    expired_cert = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2025-01-01",
        "is_trusted": False,
        "expired": True,
        "days_until_expiry": -10.0,
    }
    all_headers_present = {
        "present_headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        },
        "missing_headers": [],
        "error": None,
    }
    missing_csp_headers = {
        "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
        "missing_headers": ["Content-Security-Policy"],
        "error": None,
    }
    error_headers = {
        "present_headers": {},
        "missing_headers": [],
        "error": "Read timeout",
    }

    # Direction A: Fresh certificate defect (TLS_CERT_EXPIRED -> HIGH) with header timeout
    s_base_low = _build_scan(clean_cert, missing_csp_headers)
    s_cert_exp_hdr_err = _build_scan(expired_cert, error_headers)
    ch_dir_a = detect_changes(
        s_base_low,
        s_cert_exp_hdr_err,
        historical_baselines=[{"scan_run_id": 1001, "reports": s_base_low}],
        baseline_scan_run_id=1001,
    )
    host_inc_a = [c for c in ch_dir_a if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_a) == 1
    assert host_inc_a[0]["previous_state"] == {"band": "LOW", "score": 1}
    # Fresh TLS_CERT_EXPIRED (7) + fallback HEADER_MISSING_CSP (1) = 8 (HIGH)
    assert host_inc_a[0]["new_state"] == {"band": "HIGH", "score": 8}

    # Direction B: Fresh header finding (HEADER_MISSING_CSP -> LOW) with cert timeout (cert=None)
    s_base_info = _build_scan(clean_cert, all_headers_present)
    s_cert_none_hdr_missing = _build_scan(None, missing_csp_headers)
    ch_dir_b = detect_changes(
        s_base_info,
        s_cert_none_hdr_missing,
        historical_baselines=[{"scan_run_id": 1002, "reports": s_base_info}],
        baseline_scan_run_id=1002,
    )
    host_inc_b = [c for c in ch_dir_b if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_b) == 1
    assert host_inc_b[0]["previous_state"] == {"band": "INFO", "score": 0}
    assert host_inc_b[0]["new_state"] == {"band": "LOW", "score": 1}

    # Direction C: Concurrent RDP port exposure (3389 -> +7 pts) during partial inspection
    s_rdp_hdr_err = _build_scan(clean_cert, error_headers, ports=[80, 443, 3389])
    ch_dir_c1 = detect_changes(
        s_base_low,
        s_rdp_hdr_err,
        historical_baselines=[{"scan_run_id": 1003, "reports": s_base_low}],
        baseline_scan_run_id=1003,
    )
    host_inc_c1 = [c for c in ch_dir_c1 if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_c1) == 1
    assert host_inc_c1[0]["new_state"] == {"band": "HIGH", "score": 8}

    s_rdp_cert_none = _build_scan(None, missing_csp_headers, ports=[80, 443, 3389])
    ch_dir_c2 = detect_changes(
        s_base_low,
        s_rdp_cert_none,
        historical_baselines=[{"scan_run_id": 1004, "reports": s_base_low}],
        baseline_scan_run_id=1004,
    )
    host_inc_c2 = [c for c in ch_dir_c2 if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_c2) == 1
    assert host_inc_c2[0]["new_state"] == {"band": "HIGH", "score": 8}


def test_canonical_domain_scoring_multi_high_hosts_and_fallback():
    """Domain scoring reuses derive_domain_band across HIGH hosts and preserves domain findings."""
    from asm.scoring import derive_domain_band, score_domain_payloads

    ts = "2026-10-01T12:00:00Z"
    hosts = ["h1.example.com", "h2.example.com", "h3.example.com"]

    def _multi_host_scan(*, h3_resolved: bool, h3_rdp: bool, all_rdp: bool = True) -> dict:
        disc = []
        probe = []
        ps = []
        insp = []
        for h in hosts:
            resolved = h3_resolved if h == "h3.example.com" else True
            disc.append(
                {
                    "subdomain": h,
                    "resolved": resolved,
                    "status": "RESOLVED" if resolved else "TIMEOUT",
                    "ips": ["203.0.113.10"] if resolved else [],
                }
            )
            if not resolved:
                continue
            probe.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200, "error_type": None},
                    "https": {"reachable": True, "status_code": 200, "error_type": None},
                }
            )
            has_rdp = all_rdp and (
                (h in ("h1.example.com", "h2.example.com")) or (h == "h3.example.com" and h3_rdp)
            )
            ports = [80, 443, 3389] if has_rdp else [80, 443]
            ps.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "open_ports": [{"port": p, "state": "OPEN"} for p in ports],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            )
            insp.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "cert": {
                        "issuer": "Let's Encrypt R11",
                        "not_after": "2027-03-01",
                        "is_trusted": True,
                        "expired": False,
                    },
                    "headers": {
                        "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                        "missing_headers": ["Content-Security-Policy"],
                        "error": None,
                    },
                }
            )
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    # Scan 1: all 3 hosts resolved with RDP (3389) open -> 3 HIGH hosts (high_escalation=1, 24 pts)
    s1 = _multi_host_scan(h3_resolved=True, h3_rdp=True)
    assert s1["score"]["counts"]["high_escalation"] == 1
    assert s1["score"]["domain_band"] == "HIGH"
    assert s1["score"]["domain_score"] == 24

    # Scan 2: h3 has a 1-scan DNS timeout; fallback preserves h3's HIGH (8 pts) -> stays HIGH (24)
    s2_timeout = _multi_host_scan(h3_resolved=False, h3_rdp=True)
    ch = detect_changes(
        s1,
        s2_timeout,
        historical_baselines=[{"scan_run_id": 1101, "reports": s1}],
        baseline_scan_run_id=1101,
    )
    assert not any("RISK_BAND" in c["change_type"] for c in ch)

    # Scenario B: 10 hosts initially LOW (10 * 1 + LARGE_ATTACK_SURFACE 1 = 11, LOW).
    # Next scan: h1..h3 open RDP (3389 -> HIGH 8 pts), h3 has a header timeout (needs header
    # fallback from baseline), and h10 has a 1-scan DNS timeout (raw host count drops to 9,
    # but stabilized effective_hosts stays 10 so LARGE_ATTACK_SURFACE is preserved).
    ten_hosts = [f"h{i}.example.com" for i in range(1, 11)]

    def _ten_host_scan(*, rdp_hosts: set[str], h3_hdr_err: bool, h10_timeout: bool) -> dict:
        disc = []
        probe = []
        ps = []
        insp = []
        for h in ten_hosts:
            resolved = not (h == "h10.example.com" and h10_timeout)
            disc.append(
                {
                    "subdomain": h,
                    "resolved": resolved,
                    "status": "RESOLVED" if resolved else "TIMEOUT",
                    "ips": ["203.0.113.10"] if resolved else [],
                }
            )
            if not resolved:
                continue
            probe.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "http": {"reachable": True, "status_code": 200, "error_type": None},
                    "https": {"reachable": True, "status_code": 200, "error_type": None},
                }
            )
            ports = [80, 443, 3389] if h in rdp_hosts else [80, 443]
            ps.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "open_ports": [{"port": p, "state": "OPEN"} for p in ports],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            )
            hdrs = (
                {"present_headers": {}, "missing_headers": [], "error": "Read timeout"}
                if (h == "h3.example.com" and h3_hdr_err)
                else {
                    "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                    "missing_headers": ["Content-Security-Policy"],
                    "error": None,
                }
            )
            insp.append(
                {
                    "subdomain": h,
                    "status": "PROBED",
                    "cert": {
                        "issuer": "Let's Encrypt R11",
                        "not_after": "2027-03-01",
                        "is_trusted": True,
                        "expired": False,
                    },
                    "headers": hdrs,
                }
            )
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    s10_low = _ten_host_scan(rdp_hosts=set(), h3_hdr_err=False, h10_timeout=False)
    assert s10_low["score"]["domain_band"] == "LOW"
    assert s10_low["score"]["domain_score"] == 10
    assert any(f["id"] == "LARGE_ATTACK_SURFACE" for f in s10_low["score"]["domain_findings"])

    s10_escalated = _ten_host_scan(
        rdp_hosts={"h1.example.com", "h2.example.com", "h3.example.com"},
        h3_hdr_err=True,
        h10_timeout=True,
    )
    s10_escalated["score"]["domain_findings"].append({"id": "DOMAIN_CUSTOM_POSTURE", "points": 2})
    ch_esc = detect_changes(
        s10_low,
        s10_escalated,
        historical_baselines=[{"scan_run_id": 1102, "reports": s10_low}],
        baseline_scan_run_id=1102,
    )
    dom_inc = [c for c in ch_esc if c["change_type"] == "DOMAIN_RISK_BAND_INCREASED"]
    assert len(dom_inc) == 1
    assert dom_inc[0]["previous_state"] == {"band": "LOW", "score": 10}
    # 3 HIGH hosts (3 * 8 = 24) + 7 LOW hosts (7 * 1 = 7) + preserved domain_findings (2) = 33
    assert dom_inc[0]["new_state"] == {"band": "HIGH", "score": 33}

    band, is_esc = derive_domain_band(
        score_domain_payloads(
            "example.com",
            s1["discover"]["results"],
            s1["probe"]["results"],
            s1["portscan"]["results"],
            s1["inspect"]["results"],
        ).hosts
    )
    assert band == "HIGH" and is_esc is True


def test_unavailable_portscan_does_not_suppress_fresh_inspection_findings_and_risk_bands():
    """Unprobed portscan falls back stage-specifically without suppressing fresh inspect defects."""
    from asm.scoring import score_domain_payloads

    host = "portal.example.com"
    ts = "2026-10-01T12:00:00Z"

    def _make_scan(
        *,
        ps_probed: bool = True,
        open_ports: list[int] | None = None,
        cert_dict: dict | None = None,
        headers_dict: dict | None = None,
    ) -> dict:
        if open_ports is None:
            open_ports = [80, 443]
        disc = [
            {"subdomain": host, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
        ]
        probe = [
            {
                "subdomain": host,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
        ]
        if ps_probed:
            ps = [
                {
                    "subdomain": host,
                    "status": "PROBED",
                    "open_ports": [{"port": p, "state": "OPEN"} for p in open_ports],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        else:
            ps = [{"subdomain": host, "status": "TIMEOUT", "open_ports": [], "closed_ports": []}]
        insp = [{"subdomain": host, "status": "PROBED", "cert": cert_dict, "headers": headers_dict}]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    clean_cert = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2027-03-01",
        "is_trusted": True,
        "expired": False,
    }
    expired_cert = {
        "issuer": "Let's Encrypt R11",
        "not_after": "2025-01-01",
        "is_trusted": False,
        "expired": True,
        "days_until_expiry": -10.0,
    }
    present_headers = {
        "present_headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        },
        "missing_headers": [],
        "error": None,
    }
    missing_hsts_headers = {
        "present_headers": {"Content-Security-Policy": "default-src 'self'"},
        "missing_headers": ["Strict-Transport-Security"],
        "error": None,
    }

    # Case A: Baseline has clean cert and missing CSP (LOW, 1 pt).
    # New scan has portscan TIMEOUT, but inspect finds expired cert (HIGH, 7 pts).
    s1_base = _make_scan(
        ps_probed=True,
        open_ports=[80, 443],
        cert_dict=clean_cert,
        headers_dict={
            "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
            "missing_headers": ["Content-Security-Policy"],
            "error": None,
        },
    )
    s2_cert_exp_ps_timeout = _make_scan(
        ps_probed=False,
        cert_dict=expired_cert,
        headers_dict={
            "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
            "missing_headers": ["Content-Security-Policy"],
            "error": None,
        },
    )
    changes_a = detect_changes(
        s1_base,
        s2_cert_exp_ps_timeout,
        historical_baselines=[{"scan_run_id": 1201, "reports": s1_base}],
        baseline_scan_run_id=1201,
    )
    # 1. Finding-level event CERTIFICATE_BECAME_EXPIRED emitted
    cert_ch = [c for c in changes_a if c["change_type"] == "CERTIFICATE_BECAME_EXPIRED"]
    assert len(cert_ch) == 1
    assert cert_ch[0]["asset"] == host
    # 2. Summary HOST_RISK_BAND_INCREASED emitted (LOW -> HIGH)
    host_inc_a = [c for c in changes_a if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_a) == 1
    assert host_inc_a[0]["previous_state"] == {"band": "LOW", "score": 1}
    assert host_inc_a[0]["new_state"] == {"band": "HIGH", "score": 8}
    # 3. Summary DOMAIN_RISK_BAND_INCREASED emitted (LOW -> HIGH)
    dom_inc_a = [c for c in changes_a if c["change_type"] == "DOMAIN_RISK_BAND_INCREASED"]
    assert len(dom_inc_a) == 1
    assert dom_inc_a[0]["previous_state"] == {"band": "LOW", "score": 1}
    assert dom_inc_a[0]["new_state"] == {"band": "HIGH", "score": 8}

    # Case B: Baseline has INFO (score: 0).
    # New scan has portscan TIMEOUT, but inspect finds HSTS removed (LOW, 1 pt).
    s1_info = _make_scan(
        ps_probed=True,
        open_ports=[80, 443],
        cert_dict=clean_cert,
        headers_dict=present_headers,
    )
    s2_hsts_missing_ps_timeout = _make_scan(
        ps_probed=False,
        cert_dict=clean_cert,
        headers_dict=missing_hsts_headers,
    )
    changes_b = detect_changes(
        s1_info,
        s2_hsts_missing_ps_timeout,
        historical_baselines=[{"scan_run_id": 1202, "reports": s1_info}],
        baseline_scan_run_id=1202,
    )
    # Finding-level event SECURITY_HEADER_REMOVED emitted
    hdr_ch = [c for c in changes_b if c["change_type"] == "SECURITY_HEADER_REMOVED"]
    assert len(hdr_ch) == 1
    assert hdr_ch[0]["detail"] == "Strict-Transport-Security"
    # Summary HOST_RISK_BAND_INCREASED emitted (INFO -> LOW)
    host_inc_b = [c for c in changes_b if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc_b) == 1
    assert host_inc_b[0]["previous_state"] == {"band": "INFO", "score": 0}
    assert host_inc_b[0]["new_state"] == {"band": "LOW", "score": 1}


def test_domain_inventory_lifecycle_across_confirmation_boundaries_and_large_attack_surface():
    """Exercise host presence -> 1st absence -> confirmed removal -> continued absence -> return."""
    from asm.scoring import score_domain_payloads

    ts = "2026-10-01T12:00:00Z"
    high_host = "high.example.com"
    other_hosts = [f"h{i}.example.com" for i in range(2, 11)]  # 9 other hosts -> total 10 hosts

    def _build_inventory_scan(high_present: bool) -> dict:
        active_hosts = ([high_host] if high_present else []) + other_hosts
        disc = [
            {"subdomain": h, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
            for h in active_hosts
        ]
        probe = [
            {
                "subdomain": h,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
            for h in active_hosts
        ]
        ps = [
            {
                "subdomain": h,
                "status": "PROBED",
                "open_ports": (
                    [
                        {"port": 80, "state": "OPEN"},
                        {"port": 443, "state": "OPEN"},
                        {"port": 3389, "state": "OPEN"},
                    ]
                    if h == high_host
                    else [{"port": 80, "state": "OPEN"}, {"port": 443, "state": "OPEN"}]
                ),
                "closed_ports": [],
                "filtered_ports": [],
            }
            for h in active_hosts
        ]
        insp = [
            {
                "subdomain": h,
                "status": "PROBED",
                "cert": {
                    "issuer": "Let's Encrypt R11",
                    "not_after": "2027-03-01",
                    "is_trusted": True,
                    "expired": False,
                },
                "headers": {
                    "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                    "missing_headers": ["Content-Security-Policy"],
                    "error": None,
                },
            }
            for h in active_hosts
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {
                "domain": "example.com",
                "source": "crtsh",
                "scan_time": ts,
                "results": disc,
                "truncated": False,
            },
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    s1_present = _build_inventory_scan(high_present=True)
    # 10 hosts: high_host is HIGH (7 for 3389 + 1 for CSP = 8 pts), 9 hosts are LOW (1 pt each).
    # 10 hosts >= LARGE_ATTACK_SURFACE_THRESHOLD -> LARGE_ATTACK_SURFACE (0 pts)
    # Total score = 8 + 9 * 1 = 17 pts, domain_band = HIGH
    assert s1_present["score"]["domain_band"] == "HIGH"
    assert s1_present["score"]["domain_score"] == 17
    assert any(f["id"] == "LARGE_ATTACK_SURFACE" for f in s1_present["score"]["domain_findings"])

    s2_absent_1 = _build_inventory_scan(high_present=False)
    s3_absent_2 = _build_inventory_scan(high_present=False)
    s4_absent_3 = _build_inventory_scan(high_present=False)
    s5_reappeared = _build_inventory_scan(high_present=True)

    # Step 1: Scan 1 -> Scan 2 (First absence).
    # 1st absence is unconfirmed; effective domain score lookback stabilizes domain to stay HIGH.
    # Neither REMOVED_SUBDOMAIN nor DOMAIN_RISK_BAND_DECREASED is emitted.
    changes_step1 = detect_changes(
        s1_present,
        s2_absent_1,
        historical_baselines=[{"scan_run_id": 1301, "reports": s1_present}],
        baseline_scan_run_id=1301,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes_step1)
    assert not any("RISK_BAND" in c["change_type"] for c in changes_step1)

    # Step 2: Scan 2 -> Scan 3 (Confirmed removal = Second consecutive absence).
    # REMOVED_SUBDOMAIN emitted for high_host. Domain inventory drops to 9 hosts.
    # LARGE_ATTACK_SURFACE disappears. Domain band drops from HIGH to LOW (score 9).
    changes_step2 = detect_changes(
        s2_absent_1,
        s3_absent_2,
        historical_baselines=[
            {"scan_run_id": 1302, "reports": s2_absent_1},
            {"scan_run_id": 1301, "reports": s1_present},
        ],
        baseline_scan_run_id=1302,
    )
    rem_sub = [c for c in changes_step2 if c["change_type"] == "REMOVED_SUBDOMAIN"]
    assert len(rem_sub) == 1
    assert rem_sub[0]["asset"] == high_host
    dom_dec = [c for c in changes_step2 if c["change_type"] == "DOMAIN_RISK_BAND_DECREASED"]
    assert len(dom_dec) == 1
    assert dom_dec[0]["previous_state"] == {"band": "HIGH", "score": 17}
    assert dom_dec[0]["new_state"] == {"band": "LOW", "score": 9}

    # Step 3: Scan 3 -> Scan 4 (Continued absence = Third consecutive absence).
    # high_host was already confirmed removed on Scan 3.
    # Crucial assertion: high_host is NOT resurrected from Scan 1!
    # No duplicate REMOVED_SUBDOMAIN and no DOMAIN_RISK_BAND_INCREASED emitted!
    changes_step3 = detect_changes(
        s3_absent_2,
        s4_absent_3,
        historical_baselines=[
            {"scan_run_id": 1303, "reports": s3_absent_2},
            {"scan_run_id": 1302, "reports": s2_absent_1},
            {"scan_run_id": 1301, "reports": s1_present},
        ],
        baseline_scan_run_id=1303,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes_step3)
    assert not any("RISK_BAND" in c["change_type"] for c in changes_step3)

    # Step 4: Scan 4 -> Scan 5 (Reappearance).
    # high_host reappears in discovery. Genuine NEW_SUBDOMAIN emitted.
    # Domain inventory returns to 10 hosts (LARGE_ATTACK_SURFACE re-evaluated).
    # DOMAIN_RISK_BAND_INCREASED emitted (LOW 9 -> HIGH 17).
    changes_step4 = detect_changes(
        s4_absent_3,
        s5_reappeared,
        historical_baselines=[
            {"scan_run_id": 1304, "reports": s4_absent_3},
            {"scan_run_id": 1303, "reports": s3_absent_2},
            {"scan_run_id": 1302, "reports": s2_absent_1},
        ],
        baseline_scan_run_id=1304,
    )
    new_sub = [c for c in changes_step4 if c["change_type"] == "NEW_SUBDOMAIN"]
    assert len(new_sub) == 1
    assert new_sub[0]["asset"] == high_host
    dom_inc = [c for c in changes_step4 if c["change_type"] == "DOMAIN_RISK_BAND_INCREASED"]
    assert len(dom_inc) == 1
    assert dom_inc[0]["previous_state"] == {"band": "LOW", "score": 9}
    assert dom_inc[0]["new_state"] == {"band": "HIGH", "score": 17}


def test_score_provenance_reconstructed_effective_scores_vs_persisted_score_report():
    """Verify previous_state/new_state reflect effective posture while ScoreReport is raw."""
    from asm.scoring import score_domain_payloads

    host = "provenance.example.com"
    ts = "2026-10-01T12:00:00Z"

    def _make_scan_provenance(*, open_ports: list[int], header_err: bool) -> dict:
        disc = [
            {"subdomain": host, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
        ]
        probe = [
            {
                "subdomain": host,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
        ]
        ps = [
            {
                "subdomain": host,
                "status": "PROBED",
                "open_ports": [{"port": p, "state": "OPEN"} for p in open_ports],
                "closed_ports": [],
                "filtered_ports": [],
            }
        ]
        hdrs = (
            {"present_headers": {}, "missing_headers": [], "error": "Read timeout"}
            if header_err
            else {
                "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                "missing_headers": ["Content-Security-Policy"],
                "error": None,
            }
        )
        insp = [
            {
                "subdomain": host,
                "status": "PROBED",
                "cert": {
                    "issuer": "Let's Encrypt R11",
                    "not_after": "2027-03-01",
                    "is_trusted": True,
                    "expired": False,
                },
                "headers": hdrs,
            }
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {"domain": "example.com", "scan_time": ts, "results": disc},
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    s1_clean = _make_scan_provenance(open_ports=[80, 443], header_err=False)
    # Raw persisted ScoreReport has score=1 (missing CSP), band=LOW
    assert s1_clean["score"]["domain_score"] == 1
    assert s1_clean["score"]["domain_band"] == "LOW"

    # Scan 2: Genuine RDP exposure (3389) opens, but headers encounter a 1-scan Read timeout.
    # Raw persisted ScoreReport only evaluates portscan (3389 -> 7 pts), omitting header finding.
    s2_rdp_with_header_err = _make_scan_provenance(open_ports=[80, 443, 3389], header_err=True)
    assert s2_rdp_with_header_err["score"]["domain_score"] == 7  # Raw persisted ScoreReport value

    # Change detection reconstructs effective score: 7 (port 3389) + 1 (fallback missing CSP) = 8
    ch = detect_changes(
        s1_clean,
        s2_rdp_with_header_err,
        historical_baselines=[{"scan_run_id": 1401, "reports": s1_clean}],
        baseline_scan_run_id=1401,
    )
    host_inc = [c for c in ch if c["change_type"] == "HOST_RISK_BAND_INCREASED"]
    assert len(host_inc) == 1
    # Demonstrating difference: raw ScoreReport has score=7, but emitted new_state has score=8
    assert host_inc[0]["previous_state"] == {"band": "LOW", "score": 1}
    assert host_inc[0]["new_state"] == {"band": "HIGH", "score": 8}
    assert host_inc[0]["new_state"]["score"] != s2_rdp_with_header_err["score"]["domain_score"]


def test_domain_inventory_counterexample_truncated_absences_preserve_high_risk_host():
    """Reproduce counterexample: 2 truncated absences do not drop domain risk band.

    Scenario:
    - High-risk host is present in Scan 1.
    - Two subsequent discovery reports (Scan 2 and Scan 3) omit it because they are truncated.
    - The original presence remains within the 3-prior-scan history window.
    Assert:
    - NO REMOVED_SUBDOMAIN is emitted.
    - NO false DOMAIN_RISK_BAND_DECREASED is emitted.
    """
    from asm.scoring import score_domain_payloads

    ts = "2026-10-01T12:00:00Z"
    high_host = "high.example.com"
    other_hosts = [f"h{i}.example.com" for i in range(2, 11)]

    def _build_scan(*, high_present: bool, truncated: bool) -> dict:
        active = ([high_host] if high_present else []) + other_hosts
        disc = [
            {"subdomain": h, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
            for h in active
        ]
        probe = [
            {
                "subdomain": h,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
            for h in active
        ]
        ps = [
            {
                "subdomain": h,
                "status": "PROBED",
                "open_ports": (
                    [
                        {"port": 80, "state": "OPEN"},
                        {"port": 443, "state": "OPEN"},
                        {"port": 3389, "state": "OPEN"},
                    ]
                    if h == high_host
                    else [{"port": 80, "state": "OPEN"}, {"port": 443, "state": "OPEN"}]
                ),
                "closed_ports": [],
                "filtered_ports": [],
            }
            for h in active
        ]
        insp = [
            {
                "subdomain": h,
                "status": "PROBED",
                "cert": {
                    "issuer": "Let's Encrypt R11",
                    "not_after": "2027-03-01",
                    "is_trusted": True,
                    "expired": False,
                },
                "headers": {
                    "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                    "missing_headers": ["Content-Security-Policy"],
                    "error": None,
                },
            }
            for h in active
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {
                "domain": "example.com",
                "source": "crtsh",
                "scan_time": ts,
                "results": disc,
                "truncated": truncated,
            },
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    s1_present = _build_scan(high_present=True, truncated=False)
    assert s1_present["score"]["domain_band"] == "HIGH"
    assert s1_present["score"]["domain_score"] == 17

    # Scan 2: high_host omitted because discovery is truncated (1st unknown absence)
    s2_truncated_1 = _build_scan(high_present=False, truncated=True)

    # Scan 3: high_host omitted because discovery is truncated (2nd unknown absence)
    s3_truncated_2 = _build_scan(high_present=False, truncated=True)

    # Transition 1: Scan 1 -> Scan 2
    changes_1_2 = detect_changes(
        s1_present,
        s2_truncated_1,
        historical_baselines=[{"scan_run_id": 2001, "reports": s1_present}],
        baseline_scan_run_id=2001,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes_1_2)
    assert not any("RISK_BAND" in c["change_type"] for c in changes_1_2)

    # Transition 2: Scan 2 -> Scan 3 (The core counterexample)
    # The original presence (Scan 1) remains within the 3-prior-scan history window.
    changes_2_3 = detect_changes(
        s2_truncated_1,
        s3_truncated_2,
        historical_baselines=[
            {"scan_run_id": 2002, "reports": s2_truncated_1},
            {"scan_run_id": 2001, "reports": s1_present},
        ],
        baseline_scan_run_id=2002,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes_2_3)
    assert not any(c["change_type"] == "DOMAIN_RISK_BAND_DECREASED" for c in changes_2_3)
    assert not any("RISK_BAND" in c["change_type"] for c in changes_2_3)


def test_domain_inventory_extended_lifecycle_matrix():
    """Exercise complete lifecycle regression matrix for domain inventory and removals:

    1. Present -> truncated absence -> truncated absence -> present
    2. Present -> provider-switch absence -> absence
    3. Present -> qualifying absence -> unknown -> qualifying absence
    4. Complete history-window exhaustion (documenting uncertainty at retention boundary)
    """
    from asm.scoring import score_domain_payloads

    ts = "2026-10-01T12:00:00Z"
    high_host = "high.example.com"
    other_hosts = [f"h{i}.example.com" for i in range(2, 11)]  # 9 other hosts -> 10 total

    def _make_scan(
        *,
        high_present: bool,
        source: str = "crtsh",
        truncated: bool = False,
        empty: bool = False,
    ) -> dict:
        active = ([high_host] if high_present else []) + other_hosts
        disc = (
            []
            if empty
            else [
                {"subdomain": h, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
                for h in active
            ]
        )
        probe = [
            {
                "subdomain": h,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
            for h in active
        ]
        ps = [
            {
                "subdomain": h,
                "status": "PROBED",
                "open_ports": (
                    [
                        {"port": 80, "state": "OPEN"},
                        {"port": 443, "state": "OPEN"},
                        {"port": 3389, "state": "OPEN"},
                    ]
                    if h == high_host
                    else [{"port": 80, "state": "OPEN"}, {"port": 443, "state": "OPEN"}]
                ),
                "closed_ports": [],
                "filtered_ports": [],
            }
            for h in active
        ]
        insp = [
            {
                "subdomain": h,
                "status": "PROBED",
                "cert": {
                    "issuer": "Let's Encrypt R11",
                    "not_after": "2027-03-01",
                    "is_trusted": True,
                    "expired": False,
                },
                "headers": {
                    "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                    "missing_headers": ["Content-Security-Policy"],
                    "error": None,
                },
            }
            for h in active
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {
                "domain": "example.com",
                "source": source,
                "scan_time": ts,
                "results": disc,
                "truncated": truncated,
            },
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    # 1. Present -> truncated absence -> truncated absence -> present
    s_p1 = _make_scan(high_present=True, source="crtsh", truncated=False)
    s_t1 = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_t2 = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_p2 = _make_scan(high_present=True, source="crtsh", truncated=False)

    # Step A1: Present -> Truncated absence 1
    ch_a1 = detect_changes(
        s_p1,
        s_t1,
        historical_baselines=[{"scan_run_id": 3001, "reports": s_p1}],
        baseline_scan_run_id=3001,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_a1)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_a1)

    # Step A2: Truncated absence 1 -> Truncated absence 2
    ch_a2 = detect_changes(
        s_t1,
        s_t2,
        historical_baselines=[
            {"scan_run_id": 3002, "reports": s_t1},
            {"scan_run_id": 3001, "reports": s_p1},
        ],
        baseline_scan_run_id=3002,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_a2)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_a2)

    # Step A3: Truncated absence 2 -> Present again
    ch_a3 = detect_changes(
        s_t2,
        s_p2,
        historical_baselines=[
            {"scan_run_id": 3003, "reports": s_t2},
            {"scan_run_id": 3002, "reports": s_t1},
            {"scan_run_id": 3001, "reports": s_p1},
        ],
        baseline_scan_run_id=3003,
    )
    assert not any(c["change_type"] == "NEW_SUBDOMAIN" for c in ch_a3)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_a3)

    # 2. Present -> provider-switch absence -> absence
    s_crt = _make_scan(high_present=True, source="crtsh", truncated=False)
    s_censys_abs = _make_scan(high_present=False, source="censys", truncated=False)
    s_crt_abs = _make_scan(high_present=False, source="crtsh", truncated=False)

    # Step B1: crt.sh present -> Censys absence (provider switch = UNKNOWN)
    ch_b1 = detect_changes(
        s_crt,
        s_censys_abs,
        historical_baselines=[{"scan_run_id": 3101, "reports": s_crt}],
        baseline_scan_run_id=3101,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_b1)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_b1)

    # Step B2: Censys absence -> crt.sh absence (1st qualifying absence for crt.sh anchor)
    ch_b2 = detect_changes(
        s_censys_abs,
        s_crt_abs,
        historical_baselines=[
            {"scan_run_id": 3102, "reports": s_censys_abs},
            {"scan_run_id": 3101, "reports": s_crt},
        ],
        baseline_scan_run_id=3102,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_b2)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_b2)

    # 3. Present -> qualifying absence -> unknown -> qualifying absence
    s_c1_pres = _make_scan(high_present=True, source="crtsh", truncated=False)
    s_c2_qa = _make_scan(high_present=False, source="crtsh", truncated=False)
    s_c3_unk = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_c4_qa = _make_scan(high_present=False, source="crtsh", truncated=False)

    # Step C1: Present -> 1st QA (unconfirmed)
    ch_c1 = detect_changes(
        s_c1_pres,
        s_c2_qa,
        historical_baselines=[{"scan_run_id": 3201, "reports": s_c1_pres}],
        baseline_scan_run_id=3201,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_c1)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_c1)

    # Step C2: 1st QA -> Unknown (truncated resets qualifying absence streak)
    ch_c2 = detect_changes(
        s_c2_qa,
        s_c3_unk,
        historical_baselines=[
            {"scan_run_id": 3202, "reports": s_c2_qa},
            {"scan_run_id": 3201, "reports": s_c1_pres},
        ],
        baseline_scan_run_id=3202,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_c2)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_c2)

    # Step C3: Unknown -> QA (non-consecutive: this is only the 1st consecutive QA)
    ch_c3 = detect_changes(
        s_c3_unk,
        s_c4_qa,
        historical_baselines=[
            {"scan_run_id": 3203, "reports": s_c3_unk},
            {"scan_run_id": 3202, "reports": s_c2_qa},
            {"scan_run_id": 3201, "reports": s_c1_pres},
        ],
        baseline_scan_run_id=3203,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_c3)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_c3)

    # 4. Complete history-window exhaustion
    # Verify that when presence ages out beyond the bounded 3-prior-scan window,
    # the inventory reflects bounded window evidence exhaustion, NOT verified remediation.
    s_hist_pres = _make_scan(high_present=True, source="crtsh", truncated=False)
    s_unk_1 = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_unk_2 = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_unk_3 = _make_scan(high_present=False, source="crtsh", truncated=True)
    s_unk_4 = _make_scan(high_present=False, source="crtsh", truncated=True)

    # At Scan 3304 (retains [3303, 3302, 3301]), Scan 3301 is still within window:
    ch_win_active = detect_changes(
        s_unk_2,
        s_unk_3,
        historical_baselines=[
            {"scan_run_id": 3303, "reports": s_unk_2},
            {"scan_run_id": 3302, "reports": s_unk_1},
            {"scan_run_id": 3301, "reports": s_hist_pres},
        ],
        baseline_scan_run_id=3303,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_win_active)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_win_active)

    # At Scan 3305 (retains [3304, 3303, 3302]), Scan 3301 has aged out of the 3-prior-scan window:
    # All scans in the available window omit high_host and have 9 hosts.
    # Therefore, effective domain inventory drops to 9 hosts, LARGE_ATTACK_SURFACE is absent,
    # and domain band drops to LOW.
    ch_exhausted = detect_changes(
        s_unk_3,
        s_unk_4,
        historical_baselines=[
            {"scan_run_id": 3304, "reports": s_unk_3},
            {"scan_run_id": 3303, "reports": s_unk_2},
            {"scan_run_id": 3302, "reports": s_unk_1},
        ],
        baseline_scan_run_id=3304,
    )
    # No REMOVED_SUBDOMAIN was ever confirmed (since all absences were truncated/unknown).
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_exhausted)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_exhausted)


def test_domain_inventory_empty_discovery_distinguishes_empty_missing_and_confirmed():
    """Verify empty-inventory distinguishes empty reports, missing stages, and removals.

    1. Empty discovery report (classified UNKNOWN):
       - Previously observed HIGH domain with high-risk host (Score 17, Band HIGH).
       - Current scan has empty discovery results (results: []), classified UNKNOWN.
       - Production ScoreReport has empty hosts list (hosts: [], domain_score: 0, band: 'LOW').
       Assert: NO REMOVED_SUBDOMAIN and NO false DOMAIN_RISK_BAND_DECREASED.
    2. Missing stages (raw score only):
       - Baseline has HIGH domain. Current scan has ONLY score report (no stage reports).
       Assert: Bypasses reconstruction and consumes raw score report.
    3. Genuinely confirmed removal:
       - Baseline was present; 2 consecutive non-empty qualifying absences follow.
       Assert: Emits REMOVED_SUBDOMAIN and DOMAIN_RISK_BAND_DECREASED.
    """
    from asm.scoring import score_domain_payloads

    ts = "2026-10-01T12:00:00Z"
    high_host = "high.example.com"
    other_hosts = [f"h{i}.example.com" for i in range(2, 11)]

    def _make_full_scan(*, high_present: bool, empty_discovery: bool = False) -> dict:
        active = [] if empty_discovery else (([high_host] if high_present else []) + other_hosts)
        disc = [
            {"subdomain": h, "resolved": True, "status": "RESOLVED", "ips": ["203.0.113.10"]}
            for h in active
        ]
        probe = [
            {
                "subdomain": h,
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200, "error_type": None},
                "https": {"reachable": True, "status_code": 200, "error_type": None},
            }
            for h in active
        ]
        ps = [
            {
                "subdomain": h,
                "status": "PROBED",
                "open_ports": (
                    [
                        {"port": 80, "state": "OPEN"},
                        {"port": 443, "state": "OPEN"},
                        {"port": 3389, "state": "OPEN"},
                    ]
                    if h == high_host
                    else [{"port": 80, "state": "OPEN"}, {"port": 443, "state": "OPEN"}]
                ),
                "closed_ports": [],
                "filtered_ports": [],
            }
            for h in active
        ]
        insp = [
            {
                "subdomain": h,
                "status": "PROBED",
                "cert": {
                    "issuer": "Let's Encrypt R11",
                    "not_after": "2027-03-01",
                    "is_trusted": True,
                    "expired": False,
                },
                "headers": {
                    "present_headers": {"Strict-Transport-Security": "max-age=31536000"},
                    "missing_headers": ["Content-Security-Policy"],
                    "error": None,
                },
            }
            for h in active
        ]
        sc = score_domain_payloads("example.com", disc, probe, ps, insp).to_dict()
        return {
            "discover": {
                "domain": "example.com",
                "source": "crtsh",
                "scan_time": ts,
                "results": disc,
                "truncated": False,
            },
            "probe": {"domain": "example.com", "scan_time": ts, "results": probe},
            "portscan": {"domain": "example.com", "scan_time": ts, "results": ps},
            "inspect": {"domain": "example.com", "scan_time": ts, "results": insp},
            "score": sc,
        }

    # Case 1: Previously observed HIGH domain -> Current scan has EMPTY discovery (UNKNOWN)
    s1_high = _make_full_scan(high_present=True)
    assert s1_high["score"]["domain_band"] == "HIGH"
    assert s1_high["score"]["domain_score"] == 17

    s2_empty_disc = _make_full_scan(high_present=False, empty_discovery=True)
    # Production ScoreReport on empty discovery has 0 hosts and INFO band
    assert s2_empty_disc["score"]["hosts"] == []
    assert s2_empty_disc["score"]["domain_band"] == "INFO"
    assert s2_empty_disc["score"]["domain_score"] == 0

    ch_empty = detect_changes(
        s1_high,
        s2_empty_disc,
        historical_baselines=[{"scan_run_id": 4001, "reports": s1_high}],
        baseline_scan_run_id=4001,
    )
    # An empty discovery scan is UNKNOWN; it must NOT confirm removals or drop risk band!
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in ch_empty)
    assert not any(c["change_type"] == "DOMAIN_RISK_BAND_DECREASED" for c in ch_empty)
    assert not any("RISK_BAND" in c["change_type"] for c in ch_empty)

    # Case 2: Missing stages (bare ScoreReport without stage reports)
    # When stage reports are completely absent, change detection consumes raw values.
    s2_missing_stages = {
        "score": {
            "domain": "example.com",
            "domain_score": 0,
            "domain_band": "LOW",
            "hosts": [],
            "counts": {"high_escalation": False},
        }
    }
    ch_missing = detect_changes(
        s1_high,
        s2_missing_stages,
        historical_baselines=[{"scan_run_id": 4001, "reports": s1_high}],
        baseline_scan_run_id=4001,
    )
    assert any(c["change_type"] == "DOMAIN_RISK_BAND_DECREASED" for c in ch_missing)

    # Case 3: Genuinely confirmed removal (2 consecutive non-empty qualifying absences)
    s2_absent_qa1 = _make_full_scan(high_present=False, empty_discovery=False)
    s3_absent_qa2 = _make_full_scan(high_present=False, empty_discovery=False)

    ch_confirmed = detect_changes(
        s2_absent_qa1,
        s3_absent_qa2,
        historical_baselines=[
            {"scan_run_id": 4002, "reports": s2_absent_qa1},
            {"scan_run_id": 4001, "reports": s1_high},
        ],
        baseline_scan_run_id=4002,
    )
    rem_events = [c for c in ch_confirmed if c["change_type"] == "REMOVED_SUBDOMAIN"]
    assert len(rem_events) == 1
    assert rem_events[0]["asset"] == high_host
    dom_dec = [c for c in ch_confirmed if c["change_type"] == "DOMAIN_RISK_BAND_DECREASED"]
    assert len(dom_dec) == 1
    assert dom_dec[0]["previous_state"] == {"band": "HIGH", "score": 17}
    assert dom_dec[0]["new_state"] == {"band": "LOW", "score": 9}


def test_detect_changes_tombstone_pruning_preserves_newest_and_records_transitions():
    """In-memory tombstone pruning retains newest tombstones regardless of dict insertion order
    and records all active->removed transitions before evicting excess tombstones.
    """
    rep = {
        "discover": {
            "domain": "example.com",
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
            ],
        }
    }

    # Victim inserted BEFORE 3 older tombstones (max_tombstones=3)
    inv_forward = {
        "victim.example.com": {
            "subdomain": "victim.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 1,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 2,
            "removed_at_scan_run_id": None,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 2,
        },
        "anchor.example.com": {
            "subdomain": "anchor.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 0,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 2,
            "last_qualifying_absence_scan_run_id": None,
            "removed_at_scan_run_id": None,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 2,
        },
        "tomb-1.example.com": {
            "subdomain": "tomb-1.example.com",
            "status": "removed",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 2,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 2,
            "removed_at_scan_run_id": 2,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 2,
        },
        "tomb-2.example.com": {
            "subdomain": "tomb-2.example.com",
            "status": "removed",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 2,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 2,
            "removed_at_scan_run_id": 2,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 2,
        },
        "tomb-3.example.com": {
            "subdomain": "tomb-3.example.com",
            "status": "removed",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 2,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 2,
            "removed_at_scan_run_id": 2,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 2,
        },
    }
    inv_reverse = {k: dict(v) for k, v in reversed(list(inv_forward.items()))}

    transitions_f: dict[str, dict] = {}
    transitions_r: dict[str, dict] = {}

    ch_f = detect_changes(
        rep,
        rep,
        allow_removal=True,
        persisted_inventory=inv_forward,
        persisted_transitions=transitions_f,
        current_scan_run_id=3,
        max_tombstones=3,
    )
    ch_r = detect_changes(
        rep,
        rep,
        allow_removal=True,
        persisted_inventory=inv_reverse,
        persisted_transitions=transitions_r,
        current_scan_run_id=3,
        max_tombstones=3,
    )

    assert [c["asset"] for c in ch_f if c["change_type"] == "REMOVED_SUBDOMAIN"] == [
        "victim.example.com"
    ]
    assert [c["asset"] for c in ch_r if c["change_type"] == "REMOVED_SUBDOMAIN"] == [
        "victim.example.com"
    ]
    # Victim (removed at scan 3) must be retained in both forward and reverse dicts;
    # oldest/lowest tie-breaker (tomb-1, removed at scan 2) must be evicted.
    assert set(inv_forward.keys()) == set(inv_reverse.keys())
    assert set(inv_forward.keys()) == {
        "anchor.example.com",
        "victim.example.com",
        "tomb-2.example.com",
        "tomb-3.example.com",
    }
    assert inv_forward["victim.example.com"]["status"] == "removed"
    assert transitions_f["victim.example.com"]["status"] == "removed"
    assert "tomb-1.example.com" not in transitions_f


def test_persistent_inventory_definite_dns_resolved_timeout_nxdomain_emits_once():
    """G3.2: RESOLVED -> TIMEOUT -> NXDOMAIN emits STOPPED_RESOLVING once and preserves state."""
    host = "dev.example.com"
    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    s1_res = _disc("RESOLVED", True, ["203.0.113.10"])
    s2_timeout = _disc("TIMEOUT", False, [])
    s3_nx = _disc("NXDOMAIN", False, [])
    s4_nx_again = _disc("NXDOMAIN", False, [])

    # Scan 1: Baseline
    ch1 = detect_changes(
        {},
        s1_res,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=101,
        is_first_baseline=True,
    )
    assert ch1 == []
    assert inv[host]["last_status"] == "RESOLVED"
    assert inv[host]["last_resolved"] is True

    # Scan 2: Inconclusive TIMEOUT must NOT overwrite last definite status
    ch2 = detect_changes(
        s1_res,
        s2_timeout,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=102,
        baseline_scan_run_id=101,
    )
    assert ch2 == []
    assert inv[host]["last_seen_scan_run_id"] == 102
    assert inv[host]["consecutive_qualifying_absences"] == 0
    assert inv[host]["last_status"] == "RESOLVED"
    assert inv[host]["last_resolved"] is True

    # Scan 3: Definite NXDOMAIN -> emits STOPPED_RESOLVING once
    ch3 = detect_changes(
        s2_timeout,
        s3_nx,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=103,
        baseline_scan_run_id=102,
    )
    stopped = [c for c in ch3 if c["change_type"] == "STOPPED_RESOLVING"]
    assert len(stopped) == 1
    assert stopped[0]["asset"] == host
    assert stopped[0]["previous_state"] == {"status": "RESOLVED", "resolved": True}
    assert stopped[0]["new_state"] == {"status": "NXDOMAIN", "resolved": False}
    assert inv[host]["last_status"] == "NXDOMAIN"
    assert inv[host]["last_resolved"] is False

    # Scan 4: Sustained NXDOMAIN does not emit duplicate STOPPED_RESOLVING
    ch4 = detect_changes(
        s3_nx,
        s4_nx_again,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=104,
        baseline_scan_run_id=103,
    )
    assert ch4 == []


def test_persistent_inventory_definite_dns_nxdomain_error_resolved_emits_once():
    """G3.2: NXDOMAIN -> ERROR -> RESOLVED emits NEWLY_RESOLVING once and preserves state."""
    host = "stg.example.com"
    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    s1_nx = _disc("NXDOMAIN", False, [])
    s2_error = _disc("ERROR", False, [])
    s3_res = _disc("RESOLVED", True, ["203.0.113.20"])
    s4_res_again = _disc("RESOLVED", True, ["203.0.113.20"])

    # Scan 1: Baseline
    ch1 = detect_changes(
        {},
        s1_nx,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=201,
        is_first_baseline=True,
    )
    assert ch1 == []
    assert inv[host]["last_status"] == "NXDOMAIN"
    assert inv[host]["last_resolved"] is False

    # Scan 2: Inconclusive ERROR must NOT overwrite last definite status
    ch2 = detect_changes(
        s1_nx,
        s2_error,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=202,
        baseline_scan_run_id=201,
    )
    assert ch2 == []
    assert inv[host]["last_seen_scan_run_id"] == 202
    assert inv[host]["consecutive_qualifying_absences"] == 0
    assert inv[host]["last_status"] == "NXDOMAIN"
    assert inv[host]["last_resolved"] is False

    # Scan 3: Definite RESOLVED -> emits NEWLY_RESOLVING once
    ch3 = detect_changes(
        s2_error,
        s3_res,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=203,
        baseline_scan_run_id=202,
    )
    newly = [c for c in ch3 if c["change_type"] == "NEWLY_RESOLVING"]
    assert len(newly) == 1
    assert newly[0]["asset"] == host
    assert newly[0]["previous_state"] == {"status": "NXDOMAIN", "resolved": False}
    assert newly[0]["new_state"] == {"status": "RESOLVED", "resolved": True}
    assert inv[host]["last_status"] == "RESOLVED"
    assert inv[host]["last_resolved"] is True

    # Scan 4: Sustained RESOLVED does not emit duplicate NEWLY_RESOLVING
    ch4 = detect_changes(
        s3_res,
        s4_res_again,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=204,
        baseline_scan_run_id=203,
    )
    assert ch4 == []


def test_persistent_inventory_multiple_inconclusive_observations_between_definite():
    """G3.2: Inconclusive observations (TIMEOUT, ERROR, NO_ANSWER) preserve definite state."""
    host = "api.example.com"
    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    # 1. RESOLVED
    detect_changes(
        {},
        _disc("RESOLVED", True, ["203.0.113.1"]),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=301,
        is_first_baseline=True,
    )
    assert inv[host]["last_status"] == "RESOLVED"

    # 2. TIMEOUT -> preserved
    ch2 = detect_changes(
        _disc("RESOLVED", True, ["203.0.113.1"]),
        _disc("TIMEOUT", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=302,
        baseline_scan_run_id=301,
    )
    assert ch2 == []
    assert inv[host]["last_status"] == "RESOLVED"

    # 3. ERROR -> preserved
    ch3 = detect_changes(
        _disc("TIMEOUT", False, []),
        _disc("ERROR", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=303,
        baseline_scan_run_id=302,
    )
    assert ch3 == []
    assert inv[host]["last_status"] == "RESOLVED"

    # 4. NO_ANSWER -> preserved
    ch4 = detect_changes(
        _disc("ERROR", False, []),
        _disc("NO_ANSWER", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=304,
        baseline_scan_run_id=303,
    )
    assert ch4 == []
    assert inv[host]["last_status"] == "RESOLVED"

    # 5. NXDOMAIN -> emits STOPPED_RESOLVING once
    ch5 = detect_changes(
        _disc("NO_ANSWER", False, []),
        _disc("NXDOMAIN", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=305,
        baseline_scan_run_id=304,
    )
    stopped = [c for c in ch5 if c["change_type"] == "STOPPED_RESOLVING"]
    assert len(stopped) == 1
    assert inv[host]["last_status"] == "NXDOMAIN"

    # 6. ERROR -> preserved
    ch6 = detect_changes(
        _disc("NXDOMAIN", False, []),
        _disc("ERROR", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=306,
        baseline_scan_run_id=305,
    )
    assert ch6 == []
    assert inv[host]["last_status"] == "NXDOMAIN"

    # 7. TIMEOUT -> preserved
    ch7 = detect_changes(
        _disc("ERROR", False, []),
        _disc("TIMEOUT", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=307,
        baseline_scan_run_id=306,
    )
    assert ch7 == []
    assert inv[host]["last_status"] == "NXDOMAIN"

    # 8. RESOLVED -> emits NEWLY_RESOLVING once
    ch8 = detect_changes(
        _disc("TIMEOUT", False, []),
        _disc("RESOLVED", True, ["203.0.113.1"]),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=308,
        baseline_scan_run_id=307,
    )
    newly = [c for c in ch8 if c["change_type"] == "NEWLY_RESOLVING"]
    assert len(newly) == 1
    assert inv[host]["last_status"] == "RESOLVED"


def test_persistent_inventory_resolved_unknown_resolved_no_false_transition():
    """G3.2: RESOLVED -> UNKNOWN -> RESOLVED produces no false transitions."""
    host = "web.example.com"
    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    # Scan 1: RESOLVED
    detect_changes(
        {},
        _disc("RESOLVED", True, ["203.0.113.5"]),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=401,
        is_first_baseline=True,
    )
    assert inv[host]["last_status"] == "RESOLVED"

    # Scan 2: UNKNOWN
    ch2 = detect_changes(
        _disc("RESOLVED", True, ["203.0.113.5"]),
        _disc("UNKNOWN", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=402,
        baseline_scan_run_id=401,
    )
    assert ch2 == []
    assert inv[host]["last_status"] == "RESOLVED"

    # Scan 3: RESOLVED again -> must NOT emit NEWLY_RESOLVING
    ch3 = detect_changes(
        _disc("UNKNOWN", False, []),
        _disc("RESOLVED", True, ["203.0.113.5"]),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=403,
        baseline_scan_run_id=402,
    )
    assert ch3 == []
    assert inv[host]["last_status"] == "RESOLVED"


def test_persistent_inventory_initially_unknown_dns_preserves_baseline_semantics():
    """G3.2: Initial unknown DNS before first definite observation emits no false transition."""
    host = "first-unknown.example.com"
    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    # Scan 1: Initial observation is TIMEOUT (inconclusive)
    detect_changes(
        {},
        _disc("TIMEOUT", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=501,
        is_first_baseline=True,
    )
    assert inv[host]["last_status"] == "TIMEOUT"
    assert inv[host]["last_resolved"] is False

    # Scan 2: First definite observation is RESOLVED -> must NOT emit NEWLY_RESOLVING
    ch2 = detect_changes(
        _disc("TIMEOUT", False, []),
        _disc("RESOLVED", True, ["203.0.113.8"]),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=502,
        baseline_scan_run_id=501,
    )
    assert ch2 == []
    # Now definite DNS state is established as RESOLVED
    assert inv[host]["last_status"] == "RESOLVED"
    assert inv[host]["last_resolved"] is True

    # Scan 3: Transition to NXDOMAIN -> emits STOPPED_RESOLVING once
    ch3 = detect_changes(
        _disc("RESOLVED", True, ["203.0.113.8"]),
        _disc("NXDOMAIN", False, []),
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=503,
        baseline_scan_run_id=502,
    )
    stopped = [c for c in ch3 if c["change_type"] == "STOPPED_RESOLVING"]
    assert len(stopped) == 1
    assert inv[host]["last_status"] == "NXDOMAIN"


def test_persistent_inventory_dns_parity_with_legacy_lookback():
    """G3.2: Persistent inventory and legacy lookback emit identical transitions on sequence."""
    host = "parity.example.com"

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    s1 = _disc("RESOLVED", True, ["203.0.113.15"])
    s2 = _disc("TIMEOUT", False, [])
    s3 = _disc("NXDOMAIN", False, [])

    # Legacy lookback path
    ch_legacy = detect_changes(
        s2,
        s3,
        persisted_inventory=None,
        historical_baselines=[
            {"scan_run_id": 602, "reports": s2},
            {"scan_run_id": 601, "reports": s1},
        ],
        baseline_scan_run_id=602,
    )

    # Persistent inventory path
    inv: dict[str, dict[str, Any]] = {}
    detect_changes({}, s1, persisted_inventory=inv, current_scan_run_id=601, is_first_baseline=True)
    detect_changes(
        s1, s2, persisted_inventory=inv, current_scan_run_id=602, baseline_scan_run_id=601
    )
    ch_persistent = detect_changes(
        s2,
        s3,
        persisted_inventory=inv,
        historical_baselines=[
            {"scan_run_id": 602, "reports": s2},
            {"scan_run_id": 601, "reports": s1},
        ],
        current_scan_run_id=603,
        baseline_scan_run_id=602,
    )

    legacy_stops = [c for c in ch_legacy if c["change_type"] == "STOPPED_RESOLVING"]
    persistent_stops = [c for c in ch_persistent if c["change_type"] == "STOPPED_RESOLVING"]

    assert len(legacy_stops) == 1
    assert len(persistent_stops) == 1
    assert legacy_stops[0]["asset"] == persistent_stops[0]["asset"] == host
    assert legacy_stops[0]["previous_state"] == persistent_stops[0]["previous_state"]
    assert legacy_stops[0]["new_state"] == persistent_stops[0]["new_state"]
    assert legacy_stops[0]["baseline_scan_run_id"] == 601
    assert persistent_stops[0]["baseline_scan_run_id"] == 601


def test_persistent_inventory_definite_dns_beyond_lookback_window():
    """G3.2: Definite DNS state preserved across >3 inconclusive scans outside lookback window.

    When the last definite DNS observation is older than the 3-scan lookback window,
    the persistent inventory preserves the last definite DNS state (RESOLVED), so that
    when an opposite definite result (NXDOMAIN) arrives, STOPPED_RESOLVING is correctly
    emitted. The comparison baseline scan reference (baseline_scan_run_id) references
    the immediate baseline scan run per the ScanChange foreign key contract, without
    falsely claiming in detail or wording that the inconclusive scan was where addresses
    were returned.
    """
    host = "outside-lookback.example.com"

    def _disc(status: str, resolved: bool, ips: list[str]) -> dict[str, Any]:
        return {
            "discover": {
                "domain": "example.com",
                "source": "crt.sh",
                "results": [
                    {
                        "subdomain": host,
                        "status": status,
                        "resolved": resolved,
                        "ip_addresses": ips,
                    }
                ],
            }
        }

    s1 = _disc("RESOLVED", True, ["203.0.113.50"])
    s3 = _disc("TIMEOUT", False, [])
    s4 = _disc("TIMEOUT", False, [])
    s5 = _disc("TIMEOUT", False, [])
    s6 = _disc("NXDOMAIN", False, [])

    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}

    # Scan 1 (701): Initial RESOLVED
    detect_changes(
        {},
        s1,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=701,
        is_first_baseline=True,
    )
    assert inv[host]["last_status"] == "RESOLVED"
    assert inv[host]["last_resolved"] is True

    # Scans 2-5 (702-705): 4 consecutive TIMEOUT scans (exceeding 3-scan lookback)
    for scan_id in range(702, 706):
        ch = detect_changes(
            _disc("TIMEOUT", False, []),
            _disc("TIMEOUT", False, []),
            persisted_inventory=inv,
            persisted_transitions=transitions,
            current_scan_run_id=scan_id,
            baseline_scan_run_id=scan_id - 1,
        )
        assert len(ch) == 0
        assert inv[host]["last_status"] == "RESOLVED"
        assert inv[host]["last_resolved"] is True

    # Scan 6 (706): NXDOMAIN arrives. Historical baselines only contains the 3 recent TIMEOUTs.
    historical_baselines = [
        {"scan_run_id": 705, "reports": s5},
        {"scan_run_id": 704, "reports": s4},
        {"scan_run_id": 703, "reports": s3},
    ]

    ch6 = detect_changes(
        s5,
        s6,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        historical_baselines=historical_baselines,
        current_scan_run_id=706,
        baseline_scan_run_id=705,
    )

    stopped = [c for c in ch6 if c["change_type"] == "STOPPED_RESOLVING"]
    assert len(stopped) == 1
    change = stopped[0]
    assert change["asset"] == host
    assert change["previous_state"] == {"status": "RESOLVED", "resolved": True}
    assert change["new_state"] == {"status": "NXDOMAIN", "resolved": False}
    assert change["evidence"] == "discover"
    assert change["detail"] == ""
    # baseline_scan_run_id is the comparison baseline FK
    assert change["baseline_scan_run_id"] == 705
    # Inventory updated to NXDOMAIN
    assert inv[host]["last_status"] == "NXDOMAIN"
    assert inv[host]["last_resolved"] is False

    # Scan 7 (707): Subsequent inconclusive scan does not re-emit or clobber NXDOMAIN
    s7 = _disc("TIMEOUT", False, [])
    ch7 = detect_changes(
        s6,
        s7,
        persisted_inventory=inv,
        persisted_transitions=transitions,
        current_scan_run_id=707,
        baseline_scan_run_id=706,
    )
    assert len(ch7) == 0
    assert inv[host]["last_status"] == "NXDOMAIN"
    assert inv[host]["last_resolved"] is False


def test_bootstrap_persistent_inventory_bounded_window_and_chronology():
    """Verify bootstrap uses only the bounded 3-scan window in chronological order."""

    # Historical baselines: 5 scans provided (newest to oldest: 50, 40, 30, 20, 10).
    # Only scans 50, 40, 30 must be used (scans 20 and 10 are outside the bounded window).
    def _make_hist_scan(scan_id: int, host_list: list[str]) -> dict[str, Any]:
        return {
            "scan_run_id": scan_id,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": h, "status": "RESOLVED", "resolved": True} for h in host_list
                    ],
                }
            },
        }

    baselines = [
        _make_hist_scan(50, ["recent.example.com"]),
        _make_hist_scan(40, ["recent.example.com", "mid.example.com"]),
        _make_hist_scan(30, ["mid.example.com", "window_start.example.com"]),
        _make_hist_scan(20, ["too_old_20.example.com"]),
        _make_hist_scan(10, ["too_old_10.example.com"]),
    ]

    inv: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}
    bootstrap_persistent_inventory(
        baselines,
        persisted_inventory=inv,
        persisted_transitions=transitions,
    )

    # Scans 10 and 20 are outside the 3-scan window and unavailable
    assert "too_old_10.example.com" not in inv
    assert "too_old_20.example.com" not in inv

    # window_start was present in 30, absent in 40 (streak 1), absent in 50 (streak 2 -> removed)
    assert inv["window_start.example.com"]["status"] == "removed"
    assert inv["window_start.example.com"]["consecutive_qualifying_absences"] == 2
    assert inv["window_start.example.com"]["removed_at_scan_run_id"] == 50

    # mid was present in 30, present in 40, absent in 50 (streak 1)
    assert inv["mid.example.com"]["status"] == "active"
    assert inv["mid.example.com"]["consecutive_qualifying_absences"] == 1

    # recent was absent in 30, added in 40, present in 50 (active, streak 0)
    assert inv["recent.example.com"]["status"] == "active"
    assert inv["recent.example.com"]["consecutive_qualifying_absences"] == 0
    assert inv["recent.example.com"]["last_seen_scan_run_id"] == 50


def test_bootstrap_persistent_inventory_preserves_definite_dns_across_inconclusive():
    """Verify G3.2 definite DNS preservation across inconclusive observations during bootstrap."""
    # S3 (300): RESOLVED True
    # S2 (301): TIMEOUT False (inconclusive)
    # S1 (302): ERROR False (inconclusive)
    baselines = [
        {
            "scan_run_id": 302,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": "dns.example.com", "status": "ERROR", "resolved": False}
                    ],
                }
            },
        },
        {
            "scan_run_id": 301,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": "dns.example.com", "status": "TIMEOUT", "resolved": False}
                    ],
                }
            },
        },
        {
            "scan_run_id": 300,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": "dns.example.com", "status": "RESOLVED", "resolved": True}
                    ],
                }
            },
        },
    ]

    inv: dict[str, dict[str, Any]] = {}
    bootstrap_persistent_inventory(baselines, persisted_inventory=inv)

    # Definite state from scan 300 is preserved despite intervening inconclusive observations
    assert inv["dns.example.com"]["status"] == "active"
    assert inv["dns.example.com"]["last_status"] == "RESOLVED"
    assert inv["dns.example.com"]["last_resolved"] is True


def test_bootstrap_persistent_inventory_provider_change_streak_reset():
    """Verify provider changes or unknown observations reset absence streak during bootstrap."""
    baselines = [
        # S1 (202): crt.sh, host absent (streak becomes 1)
        {
            "scan_run_id": 202,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
                    ],
                }
            },
        },
        # S2 (201): Cert Spotter (different provider -> UNKNOWN observation, resets streak)
        {
            "scan_run_id": 201,
            "reports": {
                "discover": {
                    "source": "Cert Spotter",
                    "truncated": False,
                    "results": [
                        {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
                    ],
                }
            },
        },
        # S3 (200): crt.sh, anchor and flaky present
        {
            "scan_run_id": 200,
            "reports": {
                "discover": {
                    "source": "crt.sh",
                    "truncated": False,
                    "results": [
                        {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True},
                        {"subdomain": "flaky.example.com", "status": "RESOLVED", "resolved": True},
                    ],
                }
            },
        },
    ]

    inv: dict[str, dict[str, Any]] = {}
    bootstrap_persistent_inventory(baselines, persisted_inventory=inv)

    # flaky should have streak=1, NOT streak=2 (because S2 was a provider change resetting streak)
    assert inv["flaky.example.com"]["status"] == "active"
    assert inv["flaky.example.com"]["consecutive_qualifying_absences"] == 1


def test_bootstrap_persistent_inventory_empty_history_returns_empty():
    """Verify empty historical inputs produce empty inventory without errors."""
    inv: dict[str, dict[str, Any]] = {}
    res = bootstrap_persistent_inventory([], persisted_inventory=inv)
    assert res == {}
    assert inv == {}


def test_g3_4_capacity_check_ordering_vs_same_scan_removals_and_separate_truncation_metadata():
    """G3.4: Section 2b removals run before Section 2a additions.

    Also verifies capacity metadata is separate from provider truncation.
    """
    # 1. Capacity starvation before removals:
    # Inventory has 2 active hosts at max_active_subdomains=2.
    # old.example.com has 1 qualifying absence.
    inv: dict[str, dict[str, Any]] = {
        "anchor.example.com": {
            "subdomain": "anchor.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 0,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 2,
            "last_status": "RESOLVED",
            "last_resolved": True,
        },
        "old.example.com": {
            "subdomain": "old.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 1,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 2,
            "last_status": "RESOLVED",
            "last_resolved": True,
        },
    }

    # Scan 3: old.example.com is absent (qualifying absence #2 -> removed),
    # replacement.example.com is present. Provider did NOT truncate.
    rep3 = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "replacement.example.com", "status": "RESOLVED", "resolved": True},
            ],
        }
    }

    changes = detect_changes(
        {},
        rep3,
        persisted_inventory=inv,
        current_scan_run_id=3,
        max_active_subdomains=2,
    )

    change_types = {(c["change_type"], c["asset"]) for c in changes}
    # old.example.com was removed in Section 2b
    assert ("REMOVED_SUBDOMAIN", "old.example.com") in change_types
    assert inv["old.example.com"]["status"] == "removed"

    # Because Section 2b ran before Section 2a, replacement.example.com is admitted
    assert "replacement.example.com" in inv
    assert inv["replacement.example.com"]["status"] == "active"
    assert ("NEW_SUBDOMAIN", "replacement.example.com") in change_types
    assert sum(1 for v in inv.values() if v["status"] == "active") == 2

    # Provider truncation must remain False (not mutated in-place)
    assert rep3["discover"]["truncated"] is False
    assert rep3["discover"].get("inventory_capacity_exceeded", False) is False

    # 2. Genuine capacity overflow:
    # Inventory now has 2 active hosts. Scan 4 has 2 existing + 1 overflow host.
    rep4 = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "replacement.example.com", "status": "RESOLVED", "resolved": True},
                {"subdomain": "overflow.example.com", "status": "RESOLVED", "resolved": True},
            ],
        }
    }

    changes4 = detect_changes(
        {},
        rep4,
        persisted_inventory=inv,
        current_scan_run_id=4,
        max_active_subdomains=2,
    )

    # overflow.example.com not admitted
    assert "overflow.example.com" not in inv
    assert not any(c["asset"] == "overflow.example.com" for c in changes4)
    assert sum(1 for v in inv.values() if v["status"] == "active") == 2

    # Provider truncated remains False; separate inventory capacity metadata is recorded
    assert rep4["discover"]["truncated"] is False
    assert rep4["discover"].get("inventory_capacity_exceeded") is True
    assert rep4["discover"].get("untracked_subdomains_count") == 1


def test_g3_5_effective_domain_band_uses_persisted_inventory_beyond_lookback():
    """G3.5: Section 4 effective domain band uses persisted_inventory when available.

    When an active host is maintained in persisted_inventory (status='active',
    consecutive_qualifying_absences=1 because intermediate scans were UNKNOWN/truncated),
    its active membership in the domain is preserved even if its original discovery
    was beyond the immediate historical lookback window.
    """
    inv: dict[str, dict[str, Any]] = {
        "anchor.example.com": {
            "subdomain": "anchor.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 0,
            "first_seen_scan_run_id": 0,
            "last_seen_scan_run_id": 3,
            "last_status": "RESOLVED",
            "last_resolved": True,
        },
        "crit.example.com": {
            "subdomain": "crit.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 0,
            "first_seen_scan_run_id": 0,
            "last_seen_scan_run_id": 0,
            "last_qualifying_absence_scan_run_id": 1,
            "last_status": "RESOLVED",
            "last_resolved": True,
        },
    }

    # Historical baselines: S3 (baseline), S2, S1.
    # crit.example.com was scored in S1 (within score_scans), but its CT discovery was in S0.
    # In S3 (baseline): anchor present, CT truncated. Domain band was CRITICAL.
    # In S2: provider switch (certspotter), UNKNOWN.
    # In S1: crit.example.com scored with CRITICAL band (score=100).
    s1_rep = {
        "discover": {
            "source": "crt.sh",
            "truncated": True,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
            ],
        },
        "score": {
            "domain": "example.com",
            "domain_band": "CRITICAL",
            "domain_score": 100,
            "hosts": [
                {"subdomain": "anchor.example.com", "band": "INFO", "score": 0},
                {"subdomain": "crit.example.com", "band": "CRITICAL", "score": 100},
            ],
        },
    }
    s2_rep = {
        "discover": {
            "source": "certspotter",
            "truncated": False,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
            ],
        },
        "score": {
            "domain": "example.com",
            "domain_band": "CRITICAL",
            "domain_score": 100,
            "hosts": [{"subdomain": "anchor.example.com", "band": "INFO", "score": 0}],
        },
    }
    s3_rep = {
        "discover": {
            "source": "crt.sh",
            "truncated": True,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
            ],
        },
        "score": {
            "domain": "example.com",
            "domain_band": "CRITICAL",
            "domain_score": 100,
            "hosts": [{"subdomain": "anchor.example.com", "band": "INFO", "score": 0}],
        },
    }
    new_rep = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
            ],
        },
        "score": {
            "domain": "example.com",
            "domain_band": "INFO",
            "domain_score": 0,
            "hosts": [{"subdomain": "anchor.example.com", "band": "INFO", "score": 0}],
        },
    }

    hist = [
        {"scan_run_id": 3, "reports": s3_rep},
        {"scan_run_id": 2, "reports": s2_rep},
        {"scan_run_id": 1, "reports": s1_rep},
    ]

    changes = detect_changes(
        s3_rep,
        new_rep,
        allow_removal=True,
        historical_baselines=hist,
        baseline_scan_run_id=3,
        persisted_inventory=inv,
        current_scan_run_id=4,
    )

    # crit.example.com has QA=1 (not confirmed removed, still active in inv).
    assert inv["crit.example.com"]["status"] == "active"
    # Therefore, domain risk band must NOT prematurely drop to INFO!
    assert not any(c["change_type"] == "DOMAIN_RISK_BAND_DECREASED" for c in changes)


