"""Unit tests for the ASM command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from asm.cli import main
from asm.discovery import CertSpotterError, CrtshError
from asm.models import HostProbeResult, HostProbeStatus, SubdomainResult, UrlProbeResult


@pytest.mark.parametrize("command", ["discover", "probe", "portscan", "inspect", "score"])
@pytest.mark.parametrize("failure", ["directory", "write"])
def test_report_output_failure_returns_error(command, failure, tmp_path, capsys):
    """Report output failures must return a useful error instead of crashing."""
    source = tmp_path / "input.json"
    source.write_text(json.dumps({"domain": "example.com", "results": []}), encoding="utf-8")
    output = tmp_path / "reports"
    if failure == "directory":
        output.write_text("This is a file, not a directory.", encoding="utf-8")
    else:
        output.mkdir()

    if command == "discover":
        args = [command, "example.com"]
    elif command == "score":
        args = [command, "--discover", str(source)]
    else:
        args = [command, str(source), "--authorized"]
    args += ["--output", str(output)]

    with patch("asm.cli.fetch_crtsh_data", return_value=[]):
        if failure == "write":
            original_open = Path.open

            def open_with_write_failure(path, mode="r", *args, **kwargs):
                if mode == "w":
                    raise PermissionError("Report destination is read-only")
                return original_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", open_with_write_failure):
                result = main(args)
        else:
            result = main(args)

    assert result == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err
    assert str(output) in captured.err
    assert "Traceback" not in captured.err


class TestDiscoverCLIExecution:
    """Test suite for 'asm discover' command dispatch and error handling."""

    def test_discover_success(self, tmp_path: Path, crtsh_sample_data: list[dict], capsys):
        """Verify successful discovery run writes JSON and returns exit code 0."""
        with (
            patch("asm.cli.fetch_crtsh_data", return_value=crtsh_sample_data),
            patch("asm.cli.resolve_subdomains_concurrently") as mock_resolve,
        ):
            mock_resolve.return_value = [
                SubdomainResult(
                    subdomain="api.example.com",
                    ip_addresses=["93.184.216.34"],
                    status="RESOLVED",
                    resolved=True,
                )
            ]

            exit_code = main(["discover", "example.com", "--output", str(tmp_path)])

            assert exit_code == 0
            captured = capsys.readouterr()
            assert "=== Discovery Summary ===" in captured.out
            assert "api.example.com" not in captured.err

            # Check that report JSON file was written
            files = list(tmp_path.glob("example.com_*.json"))
            assert len(files) == 1
            report_file = files[0]

            with report_file.open("r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["domain"] == "example.com"
            assert data["source"] == "crt.sh"
            assert "scan_started_utc" in data
            assert "scan_finished_utc" in data
            assert data["counts"]["total_discovered"] > 0
            assert len(data["results"]) == 1
            assert data["results"][0]["subdomain"] == "api.example.com"

    def test_discover_invalid_domain_exit_code_1(self, capsys):
        """Verify invalid domain exits with code 1 and writes to stderr without traceback."""
        exit_code = main(["discover", "192.168.1.1"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error:" in captured.err
        assert "Traceback" not in captured.err

    def test_discover_crtsh_error_exit_code_2(self, capsys):
        """Verify crt.sh failure exits with code 2 and writes to stderr without traceback."""
        with (
            patch("asm.cli.fetch_crtsh_data", side_effect=CrtshError("crt.sh timed out")),
            patch(
                "asm.discovery.fetch_certspotter_data",
                side_effect=CertSpotterError("certspotter rate limit"),
            ),
        ):
            exit_code = main(["discover", "example.com"])
            assert exit_code == 2

            captured = capsys.readouterr()
            assert "Error:" in captured.err
            assert "crt.sh timed out" in captured.err
            assert "Traceback" not in captured.err

    def test_discover_fallback_to_certspotter_success(self, tmp_path: Path, capsys):
        """Verify crt.sh failure falls back to Cert Spotter and records source and reason."""
        with (
            patch("asm.cli.fetch_crtsh_data", side_effect=CrtshError("crt.sh 502 Bad Gateway")),
            patch(
                "asm.discovery.fetch_certspotter_data",
                return_value=([{"dns_names": ["fallback.example.com"]}], False),
            ),
            patch("asm.cli.resolve_subdomains_concurrently") as mock_resolve,
        ):
            mock_resolve.return_value = [
                SubdomainResult(
                    subdomain="fallback.example.com",
                    resolved=True,
                    ip_addresses=["1.1.1.1"],
                )
            ]
            exit_code = main(["discover", "example.com", "--output", str(tmp_path)])
            assert exit_code == 0

            files = list(tmp_path.glob("example.com_*.json"))
            assert len(files) == 1
            with files[0].open("r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["source"] == "certspotter"
            assert data["fallback_reason"] == "crt.sh 502 Bad Gateway"
            assert data["truncated"] is False
            captured = capsys.readouterr()
            assert "Source:              certspotter" in captured.out

    def test_discover_zero_subdomains_found(self, tmp_path: Path, capsys):
        """Verify handling when crt.sh returns empty results."""
        with (
            patch("asm.cli.fetch_crtsh_data", return_value=[]),
            patch("asm.cli.resolve_subdomains_concurrently") as mock_resolve,
        ):
            exit_code = main(["discover", "empty-target.com", "--output", str(tmp_path)])
            assert exit_code == 0
            mock_resolve.assert_not_called()

            captured = capsys.readouterr()
            assert "0 subdomains found" in captured.out

            files = list(tmp_path.glob("empty-target.com_*.json"))
            assert len(files) == 1
            with files[0].open("r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["counts"]["total_discovered"] == 0
            assert data["results"] == []


class TestProbeCLIExecution:
    """Test suite for 'asm probe' command dispatch and authorization gate."""

    def test_probe_missing_authorized_flag_exits_1(self, tmp_path: Path, capsys):
        """Verify omitting --authorized prints warning with domain and makes 0 requests."""
        report_file = tmp_path / "test_report.json"
        report_file.write_text(
            json.dumps({"domain": "my-target.com", "results": []}),
            encoding="utf-8",
        )

        with patch("asm.cli.probe_hosts_concurrently") as mock_probe:
            exit_code = main(["probe", str(report_file)])
            assert exit_code == 1
            mock_probe.assert_not_called()

        captured = capsys.readouterr()
        expected_msg = (
            "Active probing sends requests to my-target.com. Re-run with --authorized "
            "to confirm you own it or have written permission to test it."
        )
        assert expected_msg in captured.err
        assert "Traceback" not in captured.err

    def test_probe_missing_report_file_exits_1(self, capsys):
        """Verify non-existent report file prints error to stderr and exits 1."""
        exit_code = main(["probe", "non_existent_file.json", "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Discovery report file not found" in captured.err
        assert "Traceback" not in captured.err

    def test_probe_invalid_json_report_exits_1(self, tmp_path: Path, capsys):
        """Verify malformed JSON report file prints error to stderr and exits 1."""
        corrupt_file = tmp_path / "corrupt.json"
        corrupt_file.write_text("{not-valid-json", encoding="utf-8")

        exit_code = main(["probe", str(corrupt_file), "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Failed to parse discovery report JSON" in captured.err
        assert "Traceback" not in captured.err

    def test_probe_zero_resolved_hosts_writes_report(self, tmp_path: Path, capsys):
        """Verify report with 0 resolved hosts skips probing, writes report, and exits 0."""
        report_file = tmp_path / "unresolved_report.json"
        report_file.write_text(
            json.dumps({
                "domain": "target.org",
                "results": [
                    {"subdomain": "sub.target.org", "status": "NXDOMAIN", "resolved": False}
                ],
            }),
            encoding="utf-8",
        )

        with patch("asm.cli.probe_hosts_concurrently") as mock_probe:
            exit_code = main(["probe", str(report_file), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0
            mock_probe.assert_not_called()

        captured = capsys.readouterr()
        assert "0 resolved hosts to probe" in captured.out

        probe_files = list(tmp_path.glob("target.org_probe_*.json"))
        assert len(probe_files) == 1
        with probe_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["counts"]["hosts_probed"] == 0
        assert data["counts"]["skipped_unresolved"] == 1

    def test_probe_success_flow(self, tmp_path: Path, capsys):
        """Verify successful probe run outputs summary, writes report, and exits 0."""
        fixture_path = Path(__file__).parent / "fixtures" / "discovery_report_sample.json"

        mock_results = [
            HostProbeResult(
                subdomain="api.example.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://api.example.com/",
                    reachable=True,
                    status_code=200,
                    final_url="https://api.example.com/",
                    title="API Gateway",
                    tls_valid=True,
                ),
                live=True,
                preferred_url="https://api.example.com/",
            ),
            HostProbeResult(
                subdomain="www.example.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://www.example.com/",
                    reachable=True,
                    status_code=200,
                    final_url="https://www.example.com/",
                    title="Main Website",
                    tls_valid=True,
                ),
                live=True,
                preferred_url="https://www.example.com/",
            ),
        ]

        with patch("asm.cli.probe_hosts_concurrently", return_value=mock_results):
            exit_code = main(["probe", str(fixture_path), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0

        captured = capsys.readouterr()
        assert "=== Probe Summary ===" in captured.out
        assert "=== Live Hosts ===" in captured.out
        assert "https://api.example.com/ [200] API Gateway" in captured.out
        assert "https://www.example.com/ [200] Main Website" in captured.out

        probe_files = list(tmp_path.glob("example.com_probe_*.json"))
        assert len(probe_files) == 1
        with probe_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert data["counts"]["hosts_probed"] == 2
        assert data["counts"]["https_live"] == 2
        assert data["counts"]["skipped_unresolved"] == 2


class TestPortScanCLIExecution:
    """Test suite for 'asm portscan' command dispatch and authorization gate."""

    def test_portscan_missing_authorized_flag_exits_1(self, tmp_path: Path, capsys):
        """Verify omitting --authorized prints warning with domain and makes 0 connections."""
        report_file = tmp_path / "test_report.json"
        report_file.write_text(
            json.dumps({"domain": "my-target.com", "results": []}),
            encoding="utf-8",
        )

        with patch("asm.cli.run_port_scan") as mock_scan:
            exit_code = main(["portscan", str(report_file)])
            assert exit_code == 1
            mock_scan.assert_not_called()

        captured = capsys.readouterr()
        expected_msg = (
            "Active port scanning connects to my-target.com. Re-run with --authorized "
            "to confirm you own it or have written permission to test it."
        )
        assert expected_msg in captured.err
        assert "Traceback" not in captured.err

    def test_portscan_missing_report_file_exits_1(self, capsys):
        """Verify non-existent report file prints error to stderr and exits 1."""
        exit_code = main(["portscan", "non_existent_report.json", "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Discovery report file not found" in captured.err
        assert "Traceback" not in captured.err

    def test_portscan_zero_resolved_hosts(self, tmp_path: Path, capsys):
        """Verify report with 0 resolved hosts skips scanning, writes report, and exits 0."""
        report_file = tmp_path / "unresolved_report.json"
        report_file.write_text(
            json.dumps({
                "domain": "target.org",
                "results": [
                    {"subdomain": "sub.target.org", "status": "NXDOMAIN", "resolved": False}
                ],
            }),
            encoding="utf-8",
        )

        with patch("asm.cli.run_port_scan") as mock_scan:
            exit_code = main(["portscan", str(report_file), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0
            mock_scan.assert_not_called()

        captured = capsys.readouterr()
        assert "0 resolved hosts to scan" in captured.out

        portscan_files = list(tmp_path.glob("target.org_portscan_*.json"))
        assert len(portscan_files) == 1
        with portscan_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["counts"]["hosts_scanned"] == 0
        assert data["counts"]["skipped_unresolved"] == 1

    def test_portscan_success_flow(self, tmp_path: Path, capsys):
        """Verify successful portscan run outputs summary, writes report, and exits 0."""
        fixture_path = Path(__file__).parent / "fixtures" / "discovery_report_sample.json"

        from asm.models import HostPortScanResult, PortResult

        mock_results = [
            HostPortScanResult(
                subdomain="api.example.com",
                status=HostProbeStatus.PROBED.value,
                open_ports=[
                    PortResult(
                        port=80,
                        state="OPEN",
                        service_guess="http (guess by port)",
                        banner=None,
                        risk_flags=[],
                    ),
                    PortResult(
                        port=443,
                        state="OPEN",
                        service_guess="https (guess by port)",
                        banner=None,
                        risk_flags=[],
                    ),
                ],
                closed_ports=[21, 22],
                filtered_ports=[],
                risk_flags=[],
            ),
        ]

        with patch("asm.cli.run_port_scan", return_value=mock_results):
            exit_code = main(
                ["portscan", str(fixture_path), "--authorized", "-o", str(tmp_path)]
            )
            assert exit_code == 0

        captured = capsys.readouterr()
        assert "=== Port Scan Summary ===" in captured.out
        assert "=== Open Ports & Risk Flags ===" in captured.out
        assert "80/http (guess by port)" in captured.out

        portscan_files = list(tmp_path.glob("example.com_portscan_*.json"))
        assert len(portscan_files) == 1
        with portscan_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert data["counts"]["hosts_scanned"] == 1
        assert data["counts"]["total_open_ports"] == 2
        assert data["counts"]["skipped_unresolved"] == 2


class TestInspectCLI:
    """Test suite for 'asm inspect' CLI command and safety gate."""

    def test_inspect_without_authorized_flag_exits_1(self, tmp_path: Path, capsys):
        """Verify inspect without --authorized prints warning and exits 1 with 0 network calls."""
        probe_file = tmp_path / "probe_report.json"
        probe_file.write_text(
            json.dumps({
                "domain": "secure.org",
                "results": [
                    {
                        "subdomain": "secure.org",
                        "status": "PROBED",
                        "https": {"reachable": True},
                    }
                ],
            }),
            encoding="utf-8",
        )

        with patch("asm.cli.run_inspection") as mock_inspect:
            exit_code = main(["inspect", str(probe_file)])
            assert exit_code == 1
            mock_inspect.assert_not_called()

        captured = capsys.readouterr()
        assert "Active inspection sends requests to secure.org" in captured.err
        assert "--authorized" in captured.err
        assert "Traceback" not in captured.err

    def test_inspect_missing_report_file_exits_1(self, capsys):
        """Verify non-existent report file prints error to stderr and exits 1."""
        exit_code = main(["inspect", "non_existent_probe.json", "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Discovery report file not found" in captured.err
        assert "Traceback" not in captured.err

    def test_inspect_success_generates_report(self, tmp_path: Path, capsys):
        """Verify inspect command completes, prints summary, and writes JSON report."""
        probe_file = tmp_path / "probe_report.json"
        probe_file.write_text(
            json.dumps({
                "domain": "example.com",
                "results": [
                    {
                        "subdomain": "example.com",
                        "status": "PROBED",
                        "https": {"reachable": True},
                    }
                ],
            }),
            encoding="utf-8",
        )

        from asm.models import CertInfo, HeaderInfo, HostInspectResult, InspectReport

        mock_inspect_report = InspectReport(
            domain="example.com",
            source_report="probe_report.json",
            inspect_started_utc="2026-09-29T12:00:00+00:00",
            inspect_finished_utc="2026-09-29T12:00:02+00:00",
            counts={
                "hosts_inspected": 1,
                "certs_valid": 1,
                "certs_expired": 0,
                "certs_expiring_soon": 0,
                "hosts_missing_hsts": 0,
                "skipped_untrusted": 0,
                "skipped_private_ip": 0,
                "skipped_not_https": 0,
            },
            results=[
                HostInspectResult(
                    subdomain="example.com",
                    status="PROBED",
                    cert=CertInfo(
                        subject_cn="example.com",
                        sans=["example.com"],
                        issuer="DigiCert",
                        days_until_expiry=60.0,
                        tls_version="TLSv1.3",
                        is_trusted=True,
                        source="from_response",
                    ),
                    headers=HeaderInfo(
                        present_headers={"Strict-Transport-Security": "max-age=31536000"},
                        missing_headers=[],
                    ),
                )
            ],
        )

        with patch("asm.cli.run_inspection", return_value=mock_inspect_report):
            exit_code = main(["inspect", str(probe_file), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0

        captured = capsys.readouterr()
        assert "=== Inspection Summary ===" in captured.out
        assert "Valid Certificates:  1" in captured.out
        assert "=== Host Findings ===" in captured.out
        assert "[+] example.com" in captured.out
        assert "Cert: VALID (expires in 60 days, TLSv1.3) [from_response]" in captured.out

        inspect_files = list(tmp_path.glob("example.com_inspect_*.json"))
        assert len(inspect_files) == 1
        with inspect_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert data["counts"]["hosts_inspected"] == 1
        assert len(data["results"]) == 1


class TestScoreCLI:
    """Test suite for 'asm score' CLI command and error handling."""

    def test_score_without_discover_flag_exits_2(self) -> None:
        """Verify score command without required --discover exits with argparse error."""
        with pytest.raises(SystemExit) as exc_info:
            main(["score"])
        assert exc_info.value.code == 2

    def test_score_missing_discover_file_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Verify score command with nonexistent discover file exits 1 with clean error."""
        exit_code = main(["score", "--discover", "nonexistent_discover.json"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Discover report file not found:" in captured.err

    def test_score_domain_mismatch_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Verify score command exits 1 when report domains disagree."""
        disc_file = tmp_path / "disc.json"
        disc_file.write_text(json.dumps({"domain": "alpha.com", "results": []}))

        probe_file = tmp_path / "probe.json"
        probe_file.write_text(json.dumps({"domain": "beta.com", "results": []}))

        exit_code = main(["score", "--discover", str(disc_file), "--probe", str(probe_file)])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "does not match expected 'alpha.com'" in captured.err

    def test_score_success_workflow(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Verify full score CLI execution outputs summary and writes report JSON."""
        disc_file = tmp_path / "disc.json"
        disc_file.write_text(
            json.dumps({
                "domain": "target.org",
                "results": [
                    {"subdomain": "target.org", "resolved": True},
                ],
            })
        )

        exit_code = main(["score", "--discover", str(disc_file), "-o", str(tmp_path)])
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "ASM RISK SCORE REPORT: target.org" in captured.out
        assert "Domain Severity Band: INFO" in captured.out

        score_files = list(tmp_path.glob("target.org_score_*.json"))
        assert len(score_files) == 1
        with score_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["domain"] == "target.org"
        assert data["inputs_present"] == ["discover"]
        assert data["domain_band"] == "INFO"
        assert len(data["hosts"]) == 1

