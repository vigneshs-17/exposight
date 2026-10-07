"""Unit tests for Exposight risk scoring and multi-stage report aggregation.

All tests are completely offline (mocked / synthetic JSON fixtures, 0 network activity).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asm.models import HostScore, SeverityTier
from asm.scan_common import ReportValidationError
from asm.scoring import (
    create_finding,
    derive_domain_band,
    derive_host_band,
    evaluate_inspect_findings,
    evaluate_portscan_findings,
    evaluate_probe_findings,
    score_domain_reports,
)


class TestFindingEvaluators:
    """Test suite verifying each finding type fires on trigger condition and not on clean input."""

    def test_db_with_banner_is_critical(self) -> None:
        """User Rule 2: Exposed DB port (3306/5432/6379) OPEN with banner is CRITICAL."""
        portscan_results = [
            {
                "subdomain": "db.example.com",
                "open_ports": [
                    {
                        "port": 3306,
                        "state": "OPEN",
                        "banner": "5.7.34-log MySQL Community Server (GPL)",
                        "service_guess": "mysql",
                    }
                ],
            }
        ]
        findings = evaluate_portscan_findings(portscan_results)["db.example.com"]
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "PORT_CONFIRMED_DB"
        assert f.tier == SeverityTier.CRITICAL.value
        assert f.points == 10
        assert "5.7.34" in f.evidence

    def test_db_without_banner_is_high(self) -> None:
        """User Rule 2: Exposed DB port OPEN without banner is HIGH."""
        portscan_results = [
            {
                "subdomain": "db.example.com",
                "open_ports": [
                    {
                        "port": 5432,
                        "state": "OPEN",
                        "banner": None,
                        "service_guess": "postgresql",
                    }
                ],
            }
        ]
        findings = evaluate_portscan_findings(portscan_results)["db.example.com"]
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "PORT_EXPOSED_DB"
        assert f.tier == SeverityTier.HIGH.value
        assert f.points == 7
        assert "no banner" in f.evidence

    def test_administrative_ports_are_high(self) -> None:
        """Exposed RDP (3389), SMB (445), and Telnet (23) must be HIGH tier."""
        portscan_results = [
            {
                "subdomain": "admin.example.com",
                "open_ports": [
                    {"port": 3389, "state": "OPEN", "service_guess": "ms-wbt-server"},
                    {"port": 445, "state": "OPEN", "service_guess": "microsoft-ds"},
                    {"port": 23, "state": "OPEN", "service_guess": "telnet"},
                ],
            }
        ]
        findings = evaluate_portscan_findings(portscan_results)["admin.example.com"]
        finding_ids = {f.id for f in findings}
        assert finding_ids == {"PORT_RDP_OPEN", "PORT_SMB_OPEN", "PORT_TELNET_OPEN"}
        for f in findings:
            assert f.tier == SeverityTier.HIGH.value
            assert f.points == 7

    def test_plaintext_service_ports_are_medium(self) -> None:
        """Ports 21, 25, 110, 143 must be MEDIUM tier (and 23 is Telnet HIGH, not duplicate)."""
        portscan_results = [
            {
                "subdomain": "mail.example.com",
                "open_ports": [
                    {"port": 21, "state": "OPEN", "service_guess": "ftp"},
                    {"port": 25, "state": "OPEN", "service_guess": "smtp"},
                    {"port": 110, "state": "OPEN", "service_guess": "pop3"},
                    {"port": 143, "state": "OPEN", "service_guess": "imap"},
                ],
            }
        ]
        findings = evaluate_portscan_findings(portscan_results)["mail.example.com"]
        assert len(findings) == 4
        for f in findings:
            assert f.id == "PORT_PLAINTEXT_SERVICE"
            assert f.tier == SeverityTier.MEDIUM.value
            assert f.points == 4

    def test_expired_cert_is_high(self) -> None:
        """User Rule 3: Expired certificate is HIGH."""
        inspect_results = [
            {
                "subdomain": "expired.example.com",
                "cert": {
                    "expired": True,
                    "not_yet_valid": False,
                    "days_until_expiry": -12.5,
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["expired.example.com"]
        f = next(f for f in findings if f.id == "TLS_CERT_EXPIRED")
        assert f.tier == SeverityTier.HIGH.value
        assert f.points == 7

    def test_not_yet_valid_cert_is_high(self) -> None:
        """User Rule 3: Not-yet-valid certificate is HIGH."""
        inspect_results = [
            {
                "subdomain": "future.example.com",
                "cert": {
                    "expired": False,
                    "not_yet_valid": True,
                    "not_before": "2027-01-01T00:00:00Z",
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["future.example.com"]
        f = next(f for f in findings if f.id == "TLS_CERT_NOT_YET_VALID")
        assert f.tier == SeverityTier.HIGH.value
        assert f.points == 7

    def test_self_signed_cert_is_medium_not_high(self) -> None:
        """User Rule 3: Self-signed certificate (not expired) is MEDIUM, not HIGH."""
        inspect_results = [
            {
                "subdomain": "dev.example.com",
                "cert": {
                    "expired": False,
                    "not_yet_valid": False,
                    "issuer_equals_subject": True,
                    "issuer": "CN=DevCA",
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["dev.example.com"]
        f = next(f for f in findings if f.id == "TLS_SELF_SIGNED")
        assert f.tier == SeverityTier.MEDIUM.value
        assert f.points == 4
        assert "internal or development" in f.why_it_matters.lower()

    def test_untrusted_ca_cert_is_high(self) -> None:
        """Untrusted CA verification error (when not self-signed and not expired) is HIGH."""
        inspect_results = [
            {
                "subdomain": "untrusted.example.com",
                "cert": {
                    "expired": False,
                    "not_yet_valid": False,
                    "issuer_equals_subject": False,
                    "is_trusted": False,
                    "verify_error": "self-signed certificate in certificate chain",
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["untrusted.example.com"]
        f = next(f for f in findings if f.id == "TLS_UNTRUSTED")
        assert f.tier == SeverityTier.HIGH.value
        assert f.points == 7

    def test_hostname_mismatch_and_expiring_soon_are_medium(self) -> None:
        """Hostname mismatch and expiring soon (<= 30 days) must be MEDIUM."""
        inspect_results = [
            {
                "subdomain": "mismatch.example.com",
                "cert": {
                    "expired": False,
                    "hostname_mismatch": True,
                    "expiring_soon": True,
                    "days_until_expiry": 14.2,
                    "subject_cn": "other.com",
                    "sans": ["other.com"],
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["mismatch.example.com"]
        ids = {f.id: f for f in findings}
        assert "TLS_HOSTNAME_MISMATCH" in ids
        assert ids["TLS_HOSTNAME_MISMATCH"].tier == SeverityTier.MEDIUM.value
        assert "TLS_CERT_EXPIRING_SOON" in ids
        assert ids["TLS_CERT_EXPIRING_SOON"].tier == SeverityTier.MEDIUM.value

    def test_deprecated_tls_version_is_medium(self) -> None:
        """Negotiated TLS 1.0 or 1.1 must be MEDIUM."""
        inspect_results = [
            {
                "subdomain": "tls10.example.com",
                "cert": {
                    "expired": False,
                    "deprecated_tls": True,
                    "tls_version": "TLSv1.0",
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["tls10.example.com"]
        f = next(f for f in findings if f.id == "TLS_DEPRECATED_VERSION")
        assert f.tier == SeverityTier.MEDIUM.value
        assert f.points == 4

    def test_http_no_https_is_medium(self) -> None:
        """Live host on HTTP only (HTTPS unreachable) must be MEDIUM."""
        probe_results = [
            {
                "subdomain": "http-only.example.com",
                "status": "PROBED",
                "http": {"reachable": True, "status_code": 200},
                "https": {"reachable": False},
            }
        ]
        findings = evaluate_probe_findings(probe_results)["http-only.example.com"]
        assert len(findings) == 1
        assert findings[0].id == "HTTP_NO_HTTPS"
        assert findings[0].tier == SeverityTier.MEDIUM.value
        assert findings[0].points == 4

    def test_security_headers_and_disclosures_are_low(self) -> None:
        """Missing security headers and technology disclosures must be LOW."""
        inspect_results = [
            {
                "subdomain": "headers.example.com",
                "headers": {
                    "missing_headers": [
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                    ],
                    "server": "nginx/1.18.0",
                    "server_disclosed": True,
                },
            }
        ]
        findings = evaluate_inspect_findings(inspect_results)["headers.example.com"]
        assert len(findings) == 5
        for f in findings:
            assert f.tier == SeverityTier.LOW.value
            assert f.points == 1


class TestHostBandDerivation:
    """Test suite verifying host band derivation from worst finding tier (Rule 1)."""

    def test_host_band_from_worst_tier_critical(self) -> None:
        """Any CRITICAL finding maps host band to CRITICAL."""
        f_crit = create_finding("PORT_CONFIRMED_DB", "host.com", "portscan", "evidence")
        f_low = create_finding("HEADER_MISSING_CSP", "host.com", "inspect", "evidence")
        assert derive_host_band([f_crit, f_low]) == SeverityTier.CRITICAL.value

    def test_host_band_from_worst_tier_high(self) -> None:
        """Any HIGH finding (without CRITICAL) maps host band to HIGH."""
        f_high = create_finding("TLS_CERT_EXPIRED", "host.com", "inspect", "evidence")
        f_med = create_finding("TLS_SELF_SIGNED", "host.com", "inspect", "evidence")
        assert derive_host_band([f_high, f_med]) == SeverityTier.HIGH.value

    def test_host_band_medium_not_escalated_by_points(self) -> None:
        """User Rule 1: Host band is based on worst tier, not points alone.

        3 MEDIUM findings (12 pts) must yield host band MEDIUM, not HIGH.
        """
        f1 = create_finding("TLS_SELF_SIGNED", "host.com", "inspect", "evidence")
        f2 = create_finding("TLS_HOSTNAME_MISMATCH", "host.com", "inspect", "evidence")
        f3 = create_finding("HTTP_NO_HTTPS", "host.com", "probe", "evidence")
        assert (f1.points + f2.points + f3.points) == 12
        assert derive_host_band([f1, f2, f3]) == SeverityTier.MEDIUM.value

    def test_host_band_low_only(self) -> None:
        """Only LOW findings map host band to LOW."""
        f1 = create_finding("HEADER_MISSING_HSTS", "host.com", "inspect", "evidence")
        f2 = create_finding("HEADER_MISSING_CSP", "host.com", "inspect", "evidence")
        assert derive_host_band([f1, f2]) == SeverityTier.LOW.value

    def test_clean_host_is_info(self) -> None:
        """No findings yields INFO band."""
        assert derive_host_band([]) == SeverityTier.INFO.value


class TestDomainBandDerivation:
    """Test suite verifying domain band derivation based on host bands (Rule 4)."""

    def test_any_critical_host_yields_domain_critical(self) -> None:
        hosts = [
            HostScore(subdomain="a.com", score=10, band=SeverityTier.CRITICAL.value),
            HostScore(subdomain="b.com", score=1, band=SeverityTier.LOW.value),
        ]
        band, _ = derive_domain_band(hosts)
        assert band == SeverityTier.CRITICAL.value

    def test_single_high_host_yields_domain_high(self) -> None:
        hosts = [
            HostScore(subdomain="a.com", score=7, band=SeverityTier.HIGH.value),
            HostScore(subdomain="b.com", score=1, band=SeverityTier.LOW.value),
        ]
        band, is_escalated = derive_domain_band(hosts)
        assert band == SeverityTier.HIGH.value
        assert is_escalated is False

    def test_multiple_high_hosts_escalation(self) -> None:
        """3 or more HIGH hosts flags is_high_escalated."""
        hosts = [
            HostScore(subdomain="h1.com", score=7, band=SeverityTier.HIGH.value),
            HostScore(subdomain="h2.com", score=7, band=SeverityTier.HIGH.value),
            HostScore(subdomain="h3.com", score=7, band=SeverityTier.HIGH.value),
        ]
        band, is_escalated = derive_domain_band(hosts)
        assert band == SeverityTier.HIGH.value
        assert is_escalated is True

    def test_medium_only_yields_domain_medium(self) -> None:
        hosts = [
            HostScore(subdomain="a.com", score=4, band=SeverityTier.MEDIUM.value),
            HostScore(subdomain="b.com", score=1, band=SeverityTier.LOW.value),
        ]
        band, _ = derive_domain_band(hosts)
        assert band == SeverityTier.MEDIUM.value

    def test_low_only_yields_domain_low(self) -> None:
        hosts = [
            HostScore(subdomain="a.com", score=1, band=SeverityTier.LOW.value),
        ]
        band, _ = derive_domain_band(hosts)
        assert band == SeverityTier.LOW.value

    def test_clean_domain_yields_info(self) -> None:
        hosts = [
            HostScore(subdomain="a.com", score=0, band=SeverityTier.INFO.value),
        ]
        band, _ = derive_domain_band(hosts)
        assert band == SeverityTier.INFO.value


class TestScoreMultiStageAggregation:
    """Test suite for full score_domain_reports aggregation pipeline."""

    def test_full_pipeline_with_all_reports(self, tmp_path: Path) -> None:
        """Verify aggregation across all 4 stages with multiple finding types."""
        domain = "corp.test"

        # 1. Discover report
        disc_file = tmp_path / "discover.json"
        disc_file.write_text(
            json.dumps({
                "domain": domain,
                "results": [
                    {"subdomain": "clean.corp.test", "resolved": True},
                    {"subdomain": "db.corp.test", "resolved": True},
                    {"subdomain": "web.corp.test", "resolved": True},
                ],
            })
        )

        # 2. Probe report
        probe_file = tmp_path / "probe.json"
        probe_file.write_text(
            json.dumps({
                "domain": domain,
                "results": [
                    {
                        "subdomain": "clean.corp.test",
                        "status": "PROBED",
                        "http": {"reachable": True},
                        "https": {"reachable": True},
                    },
                    {
                        "subdomain": "web.corp.test",
                        "status": "PROBED",
                        "http": {"reachable": True, "status_code": 200},
                        "https": {"reachable": False},  # HTTP-only!
                    },
                ],
            })
        )

        # 3. Portscan report
        portscan_file = tmp_path / "portscan.json"
        portscan_file.write_text(
            json.dumps({
                "domain": domain,
                "results": [
                    {
                        "subdomain": "db.corp.test",
                        "status": "PROBED",
                        "open_ports": [
                            {
                                "port": 3306,
                                "state": "OPEN",
                                "banner": "MySQL 8.0.28",
                                "service_guess": "mysql",
                            }
                        ],
                    }
                ],
            })
        )

        # 4. Inspect report
        inspect_file = tmp_path / "inspect.json"
        inspect_file.write_text(
            json.dumps({
                "domain": domain,
                "results": [
                    {
                        "subdomain": "clean.corp.test",
                        "status": "PROBED",
                        "cert": {"expired": False, "is_trusted": True},
                        "headers": {"missing_headers": ["Content-Security-Policy"]},
                    }
                ],
            })
        )

        report = score_domain_reports(
            discover_path=str(disc_file),
            probe_path=str(probe_file),
            portscan_path=str(portscan_file),
            inspect_path=str(inspect_file),
        )

        assert report.domain == domain
        # Due to confirmed DB on db.corp.test
        assert report.domain_band == SeverityTier.CRITICAL.value

        # Verify host ordering: worst-first
        hosts_order = [h.subdomain for h in report.hosts]
        assert hosts_order[0] == "db.corp.test"  # CRITICAL (10 pts)
        assert hosts_order[1] == "web.corp.test"  # MEDIUM (4 pts HTTP-only)
        assert hosts_order[2] == "clean.corp.test"  # LOW (1 pt CSP)

        db_host = report.hosts[0]
        assert db_host.band == SeverityTier.CRITICAL.value
        assert db_host.score == 10
        assert db_host.findings[0].id == "PORT_CONFIRMED_DB"

    def test_missing_optional_inputs_handled(self, tmp_path: Path) -> None:
        """Scoring with only discover report must succeed and report inputs_present."""
        disc_file = tmp_path / "discover.json"
        disc_file.write_text(
            json.dumps({
                "domain": "alone.test",
                "results": [
                    {"subdomain": "alone.test", "resolved": True},
                ],
            })
        )

        report = score_domain_reports(discover_path=str(disc_file))
        assert report.domain == "alone.test"
        assert report.inputs_present == ["discover"]
        assert report.domain_band == SeverityTier.INFO.value
        assert report.domain_score == 0
        assert len(report.hosts) == 1
        assert report.hosts[0].band == SeverityTier.INFO.value

    def test_mismatched_domains_raises_validation_error(self, tmp_path: Path) -> None:
        """Reports from different domains must raise ReportValidationError."""
        disc_file = tmp_path / "discover.json"
        disc_file.write_text(json.dumps({"domain": "alpha.com", "results": []}))

        probe_file = tmp_path / "probe.json"
        probe_file.write_text(json.dumps({"domain": "beta.com", "results": []}))

        with pytest.raises(ReportValidationError) as exc_info:
            score_domain_reports(discover_path=str(disc_file), probe_path=str(probe_file))
        assert "does not match expected 'alpha.com'" in str(exc_info.value)

    def test_malformed_report_raises_validation_error(self, tmp_path: Path) -> None:
        """Malformed JSON or missing fields must raise ReportValidationError."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not json at all!")

        with pytest.raises(ReportValidationError):
            score_domain_reports(discover_path=str(bad_json))
