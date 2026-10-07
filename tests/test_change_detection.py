"""Unit tests for Exposight change detection engine (src/asm/changes.py)."""

from __future__ import annotations

from datetime import UTC, datetime

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

    # Case 1: Timeout on HTTPS
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
    changes_timeout = detect_changes(baseline, timeout_scan)
    assert not any(c["change_type"] == "HTTPS_LOST" for c in changes_timeout)

    # Case 2: Definite CONNECT_ERROR on HTTPS
    connect_err_scan = {
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
    changes_err = detect_changes(baseline, connect_err_scan)
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

    # 1. Baseline Reports (v1 dataclass -> to_dict)
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
            SubdomainResult(
                subdomain="old.v1-company.com",
                ip_addresses=["1.2.3.5"],
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
                    url="https://app.v1-company.com", reachable=True, status_code=200
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

    changes = detect_changes(baseline_bundle, new_bundle)
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


