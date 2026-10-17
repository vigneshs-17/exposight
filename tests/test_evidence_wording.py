"""Tests for evidence-based customer-facing wording across UI templates and email digests.

Verifies that:
1. Existing API/database change_type identifiers remain unchanged.
2. PORT_NEWLY_OPEN covers both first observation and reopening after CLOSED without
   claiming first-ever observation or service creation time.
3. PORT_NO_LONGER_OPEN describes explicit connection refusal (CLOSED) and never conflates
   refusal with timeout, packet drop, or unresponsive hosts (which map to FILTERED).
4. FILTERED on the landing page is described as an inconclusive connection result (such as
   a timeout or unreachable error) rather than equating all FILTERED results with no response.
5. CERTIFICATE_CHANGED describes differences in the certificate presented to the scanner
   without claiming administrative rotation or known CDN/alternate edge behavior.
6. NEW_SUBDOMAIN and REMOVED_SUBDOMAIN cover both initial discovery and rediscovery outside
   current tracked inventory without claiming first-ever discovery or asset deletion.
7. NEWLY_RESOLVING and STOPPED_RESOLVING match actual detector emission branches (requiring
   compared NXDOMAIN <-> RESOLVED transitions, never missing/TIMEOUT/ERROR baselines).
8. Scan detail template and alert email digest render these descriptions along actual
   production data paths while preserving viewer privacy and remediation instructions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from asm.alerts.digest import build_alert_digest
from asm.api.routes_ui import templates_env
from asm.change_wording import CHANGE_DESCRIPTIONS, describe_change
from asm.changes import detect_changes


def test_describe_change_port_newly_open_covers_initial_and_reopening():
    """PORT_NEWLY_OPEN covers both initial observation and reopening without claiming
    first-ever observation or creation time.
    """
    desc = describe_change("PORT_NEWLY_OPEN", "3306")
    assert desc == (
        "This scan observed the port accepting connections. The comparison evidence "
        "did not establish it as open. This does not establish when the service "
        "became reachable."
    )
    assert "first" not in desc.lower()

    # Verify against actual production detector reopening path (OPEN -> CLOSED -> OPEN)
    scan_1 = {
        "portscan": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "open_ports": [{"port": 5432, "state": "OPEN", "service_guess": "postgresql"}],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        }
    }
    scan_2 = {
        "portscan": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "open_ports": [],
                    "closed_ports": [5432],
                    "filtered_ports": [],
                }
            ]
        }
    }
    scan_3 = {
        "portscan": {
            "results": [
                {
                    "subdomain": "api.example.com",
                    "status": "PROBED",
                    "open_ports": [{"port": 5432, "state": "OPEN", "service_guess": "postgresql"}],
                    "closed_ports": [],
                    "filtered_ports": [],
                }
            ]
        }
    }
    reopened = detect_changes(
        scan_2,
        scan_3,
        historical_baselines=[
            {"scan_run_id": 2, "reports": scan_2},
            {"scan_run_id": 1, "reports": scan_1},
        ],
        baseline_scan_run_id=2,
        current_scan_run_id=3,
    )
    port_changes = [c for c in reopened if c["change_type"] == "PORT_NEWLY_OPEN"]
    assert len(port_changes) == 1
    assert port_changes[0]["previous_state"] == {"port": 5432, "state": "CLOSED"}
    assert describe_change(port_changes[0]["change_type"], port_changes[0]["detail"]) == desc


def test_describe_change_port_closed_states_refusal_without_timeout_conflation():
    """PORT_NO_LONGER_OPEN strictly describes connection refusal, never timeout/unresponsive."""
    desc = describe_change("PORT_NO_LONGER_OPEN", "22")
    assert "refused the scanner's connection" in desc
    assert "does not show why the connection was refused" in desc
    forbidden_terms = (
        "timeout",
        "timed out",
        "unresponsive",
        "dropped",
        "packet loss",
        "shut down",
    )
    for term in forbidden_terms:
        assert term not in desc.lower(), f"Forbidden term {term!r} found in {desc!r}"


def test_describe_change_certificate_variants_state_presentation_difference_only():
    """CERTIFICATE_CHANGED variants describe the certificate presented without claiming
    rotation or CDN behavior.
    """
    desc_issuer = describe_change("CERTIFICATE_CHANGED", "issuer")
    assert "certificate presented to the scanner has a different issuer" in desc_issuer
    assert "does not by itself show why the certificate differs" in desc_issuer

    desc_expiry = describe_change("CERTIFICATE_CHANGED", "not_after")
    assert "certificate presented to the scanner has a different expiry date" in desc_expiry
    assert "does not by itself show why the certificate differs" in desc_expiry

    desc_remediated = describe_change("CERTIFICATE_CHANGED", "")
    assert "certificate problem reported in an earlier scan was not found" in desc_remediated

    desc_fallback = describe_change("CERTIFICATE_CHANGED", "other_field")
    assert "certificate presented to the scanner differs" in desc_fallback

    forbidden_cert_terms = (
        "cdn",
        "edge",
        "rotated",
        "rotation",
        "migrated",
        "migration",
        "authorized",
    )
    for variant in (desc_issuer, desc_expiry, desc_remediated, desc_fallback):
        for forbidden in forbidden_cert_terms:
            assert forbidden not in variant.lower()


def test_describe_change_discovery_and_dns_verified_against_detector_branches():
    """Discovery and DNS descriptions match actual detector branches, including rediscovery
    and strict NXDOMAIN <-> RESOLVED transitions.
    """
    new_sub = describe_change("NEW_SUBDOMAIN", "")
    assert new_sub == (
        "This name appeared in discovery results outside the current tracked "
        "inventory. It may be newly discovered or previously observed."
    )
    assert "first" not in new_sub.lower()

    rem_sub = describe_change("REMOVED_SUBDOMAIN", "")
    assert "missing from discovery results" in rem_sub
    assert "does not confirm the name or its services were deleted" in rem_sub

    # Verify rediscovery after confirmed removal emits NEW_SUBDOMAIN with the same description
    inv: dict[str, dict] = {
        "old.example.com": {
            "subdomain": "old.example.com",
            "status": "removed",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 2,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_qualifying_absence_scan_run_id": 3,
            "removed_at_scan_run_id": 3,
            "last_status": "RESOLVED",
            "last_resolved": True,
            "last_applied_scan_run_id": 3,
        }
    }
    redisc_scan = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {
                    "subdomain": "old.example.com",
                    "status": "RESOLVED",
                    "resolved": True,
                    "ip_addresses": ["203.0.113.10"],
                }
            ],
        }
    }
    redisc_changes = detect_changes(
        {"discover": {"source": "crt.sh", "truncated": False, "results": []}},
        redisc_scan,
        persisted_inventory=inv,
        baseline_scan_run_id=3,
        current_scan_run_id=4,
    )
    assert [c["change_type"] for c in redisc_changes] == ["NEW_SUBDOMAIN"]
    assert describe_change(redisc_changes[0]["change_type"], redisc_changes[0]["detail"]) == new_sub

    # Verify DNS descriptions and confirm TIMEOUT/missing baselines do not emit DNS transitions
    newly_res = describe_change("NEWLY_RESOLVING", "")
    assert "returned addresses after an earlier compared lookup returned NXDOMAIN" in newly_res
    assert "does not establish when the DNS record changed" in newly_res

    stopped_res = describe_change("STOPPED_RESOLVING", "")
    assert "returned NXDOMAIN (name does not exist) after an earlier compared lookup" in stopped_res
    assert "does not confirm the asset was deleted" in stopped_res

    timeout_base = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {
                    "subdomain": "flaky.example.com",
                    "status": "TIMEOUT",
                    "resolved": False,
                    "ip_addresses": [],
                }
            ],
        }
    }
    resolved_now = {
        "discover": {
            "source": "crt.sh",
            "truncated": False,
            "results": [
                {
                    "subdomain": "flaky.example.com",
                    "status": "RESOLVED",
                    "resolved": True,
                    "ip_addresses": ["203.0.113.20"],
                }
            ],
        }
    }
    assert (
        detect_changes(timeout_base, resolved_now, baseline_scan_run_id=1, current_scan_run_id=2)
        == []
    )


def test_describe_change_unmapped_types_return_empty_string():
    """Types without special ambiguity overrides return empty string cleanly."""
    assert describe_change("SECURITY_HEADER_REMOVED", "Strict-Transport-Security") == ""
    assert describe_change("HOST_RISK_BAND_INCREASED", "") == ""
    assert describe_change(None, None) == ""
    assert describe_change("", "") == ""


def test_build_alert_digest_wording_singular_and_plural():
    """Alert email digest uses evidence-based subject, heading, Observed lines, and footer."""
    single_change = [
        {
            "change_type": "PORT_NEWLY_OPEN",
            "category": "exposure",
            "severity": "HIGH",
            "asset": "db.example.com",
            "detail": "5432",
            "evidence": "portscan",
        }
    ]
    subj_1, body_1 = build_alert_digest(
        domain_name="example.com",
        scan_run_id=101,
        changes=single_change,
        triggering_changes=single_change,
    )
    assert subj_1 == "[Exposight] HIGH: 1 exposure change observed on example.com"
    assert "new exposure" not in subj_1.lower()
    assert "Exposure Changes at or Above Your Alert Threshold (1):" in body_1
    assert f"Observed: {CHANGE_DESCRIPTIONS['PORT_NEWLY_OPEN']}" in body_1
    assert "when Exposight observed a difference, not when or why it happened." in body_1

    multi_changes = [
        single_change[0],
        {
            "change_type": "SECURITY_HEADER_REMOVED",
            "category": "exposure",
            "severity": "MEDIUM",
            "asset": "app.example.com",
            "detail": "Content-Security-Policy",
            "evidence": "inspect",
        },
    ]
    subj_2, body_2 = build_alert_digest(
        domain_name="example.com",
        scan_run_id=102,
        changes=multi_changes,
        triggering_changes=multi_changes,
    )
    assert subj_2 == "[Exposight] HIGH: 2 exposure changes observed on example.com"
    assert "Exposure Changes at or Above Your Alert Threshold (2):" in body_2
    assert body_2.count("Observed:") == 1


def test_scan_detail_template_renders_change_descriptions_and_coverage_notice():
    """partials/scan_detail.html preserves change_type codes and renders descriptions
    plus truncation notice.
    """
    template = templates_env.get_template("partials/scan_detail.html")

    org = SimpleNamespace(id=1, name="Acme Org")
    domain = SimpleNamespace(id=10, name="example.com")
    scan_run = SimpleNamespace(
        id=55,
        status="succeeded",
        trigger="scheduled",
        created_at=datetime(2026, 10, 17, 12, 0, tzinfo=UTC),
        error=None,
        change_detection={"status": "computed"},
    )
    changes = [
        SimpleNamespace(
            severity="HIGH",
            category="exposure",
            change_type="PORT_NEWLY_OPEN",
            asset="api.example.com",
            detail="22",
            evidence="portscan",
        ),
        SimpleNamespace(
            severity="INFO",
            category="exposure",
            change_type="PORT_NO_LONGER_OPEN",
            asset="api.example.com",
            detail="5432",
            evidence="portscan",
        ),
        SimpleNamespace(
            severity="INFO",
            category="exposure",
            change_type="CERTIFICATE_CHANGED",
            asset="www.example.com",
            detail="issuer",
            evidence="inspect",
        ),
        SimpleNamespace(
            severity="INFO",
            category="exposure",
            change_type="NEW_SUBDOMAIN",
            asset="stage.example.com",
            detail="",
            evidence="discover",
        ),
        SimpleNamespace(
            severity="INFO",
            category="exposure",
            change_type="REMOVED_SUBDOMAIN",
            asset="old.example.com",
            detail="",
            evidence="discover",
        ),
    ]

    notice = "Provider (crt.sh) entry or page limit reached. Discovery may be incomplete."
    html = template.render(
        org=org,
        domain=domain,
        scan_run=scan_run,
        status_display="Succeeded",
        duration="12s",
        pipeline_stages=[],
        fix_first=None,
        scan_changes=changes,
        should_poll=False,
        is_stale_active=False,
        user_role="viewer",
        truncation_notice=notice,
    )

    for ctype in (
        "PORT_NEWLY_OPEN",
        "PORT_NO_LONGER_OPEN",
        "CERTIFICATE_CHANGED",
        "NEW_SUBDOMAIN",
        "REMOVED_SUBDOMAIN",
    ):
        assert f"<code>{ctype}</code>" in html

    assert "This scan observed the port accepting connections." in html
    assert "refused the scanner&#39;s connection in this scan." in html
    assert "certificate presented to the scanner has a different issuer" in html
    assert (
        "outside the current tracked inventory. It may be newly discovered or previously observed."
        in html
    )
    assert "does not confirm the name or its services were deleted." in html

    assert "Differences between what this scan observed and what earlier scans observed." in html
    assert "Provider (crt.sh) entry or page limit reached. Discovery may be incomplete." in html


def test_landing_template_renders_updated_evidence_copy():
    """landing.html describes FILTERED as an inconclusive connection result (e.g. timeout or
    unreachable error) rather than equating all FILTERED results with no response.
    """
    template = templates_env.get_template("landing.html")
    html = template.render(
        txt_example="exposight-verification=token",
        txt_label="_exposight-verification.example.com",
    )
    assert "port observed open" in html
    assert (
        "open, closed (connection refused) or filtered (inconclusive connection result, "
        "such as a timeout or unreachable error)"
    ) in html
    assert "filtered (no response)" not in html
    assert "subdomains outside the tracked inventory, ports observed accepting connections" in html


def test_db_route_scan_detail_and_viewer_alert_privacy(client, db_session):
    """End-to-end route check: scan detail renders evidence descriptions, remediation copy,
    and viewer alert notifications keep recipient/error redaction intact.
    """
    from uuid import UUID

    from asm.db.models import (
        AlertNotification,
        Domain,
        Membership,
        Organization,
        ScanChange,
        ScanResult,
        ScanRun,
    )

    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    org = Organization(name="Wording Route Org")
    db_session.add(org)
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=test_user_id, role="viewer"))

    domain = Domain(
        org_id=org.id,
        name="wording.example.com",
        verification_status="verified",
        verification_token="tok-wording",
    )
    db_session.add(domain)
    db_session.flush()

    scan_run = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
        change_detection={"status": "computed"},
    )
    db_session.add(scan_run)
    db_session.flush()

    why_msg = "Restrict database access to internal networks."
    db_session.add_all(
        [
            ScanResult(
                scan_run_id=scan_run.id,
                stage="discover",
                report={
                    "truncated": True,
                    "truncation_reason": "provider_entry_limit",
                    "source": "crt.sh",
                    "counts": {"total_discovered": 100},
                },
            ),
            ScanResult(
                scan_run_id=scan_run.id,
                stage="score",
                report={
                    "domain_score": 25,
                    "domain_band": "HIGH",
                    "hosts": [
                        {
                            "subdomain": "db.wording.example.com",
                            "findings": [
                                {
                                    "id": "PORT_EXPOSED_DB",
                                    "tier": "HIGH",
                                    "title": "Exposed Database Port (5432)",
                                    "why_it_matters": why_msg,
                                    "host": "db.wording.example.com",
                                    "port": 5432,
                                    "points": 25,
                                    "evidence": "5432/tcp OPEN",
                                }
                            ],
                        }
                    ],
                },
            ),
            ScanChange(
                domain_id=domain.id,
                scan_run_id=scan_run.id,
                baseline_scan_run_id=scan_run.id,
                change_type="PORT_NEWLY_OPEN",
                category="exposure",
                severity="HIGH",
                asset="db.wording.example.com",
                detail="5432",
                evidence="portscan",
                observed_at=datetime.now(UTC),
            ),
            ScanChange(
                domain_id=domain.id,
                scan_run_id=scan_run.id,
                baseline_scan_run_id=scan_run.id,
                change_type="PORT_NO_LONGER_OPEN",
                category="exposure",
                severity="INFO",
                asset="ssh.wording.example.com",
                detail="22",
                evidence="portscan",
                observed_at=datetime.now(UTC),
            ),
            ScanChange(
                domain_id=domain.id,
                scan_run_id=scan_run.id,
                baseline_scan_run_id=scan_run.id,
                change_type="CERTIFICATE_CHANGED",
                category="exposure",
                severity="INFO",
                asset="www.wording.example.com",
                detail="not_after",
                evidence="inspect",
                observed_at=datetime.now(UTC),
            ),
        ]
    )

    subj, body = build_alert_digest(
        domain_name=domain.name,
        scan_run_id=scan_run.id,
        changes=[
            {
                "change_type": "PORT_NEWLY_OPEN",
                "category": "exposure",
                "severity": "HIGH",
                "asset": "db.wording.example.com",
                "detail": "5432",
                "evidence": "portscan",
            }
        ],
        triggering_changes=[
            {
                "change_type": "PORT_NEWLY_OPEN",
                "category": "exposure",
                "severity": "HIGH",
                "asset": "db.wording.example.com",
                "detail": "5432",
                "evidence": "portscan",
            }
        ],
    )
    db_session.add(
        AlertNotification(
            domain_id=domain.id,
            scan_run_id=scan_run.id,
            recipient="secret-ops@wording.example.com",
            subject=subj,
            body=body,
            status="failed",
            attempts=2,
            max_attempts=3,
            last_error="SMTP 550 mailbox unavailable for secret-ops@wording.example.com",
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{org.id}/scans/{scan_run.id}")
    assert resp.status_code == 200
    assert "Restrict database access to internal networks." in resp.text
    assert "This scan observed the port accepting connections." in resp.text
    assert "refused the scanner&#39;s connection in this scan." in resp.text
    assert "certificate presented to the scanner has a different expiry date" in resp.text
    assert resp.text.count("<strong>Partial coverage:</strong>") == 2

    notif_resp = client.get(f"/ui/orgs/{org.id}/domains/{domain.id}/alert-notifications")
    assert notif_resp.status_code == 200
    assert "[Exposight] HIGH: 1 exposure change observed on wording.example.com" in notif_resp.text
    assert "Observed: This scan observed the port accepting connections." in notif_resp.text
    assert "secret-ops@wording.example.com" not in notif_resp.text
    assert "SMTP 550 mailbox unavailable" not in notif_resp.text
