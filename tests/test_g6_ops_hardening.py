"""Tests for G6 Operations Hardening (Item 9).

Covers:
1. Encrypted off-host backup script with age (public key only on host, documented restore test).
2. uvicorn --forwarded-allow-ips limited strictly to Caddy (not the whole subnet or wildcard).
3. Redirect-port scope defense-in-depth in asm.scan_common (default ports 80/443 only).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestRedirectPortScopeDefenseInDepth:
    """G6.3: scan_common.is_redirect_target_safe enforces standard ports (80/443) and scope."""

    def test_scan_common_has_is_redirect_target_safe(self):
        """scan_common must export is_redirect_target_safe."""
        from asm.scan_common import is_redirect_target_safe

        # Standard HTTP and HTTPS URLs must pass
        assert is_redirect_target_safe("https://example.com/path", "example.com") is True
        assert is_redirect_target_safe("http://example.com/path", "example.com") is True
        assert is_redirect_target_safe("https://api.example.com:443/login", "example.com") is True
        assert is_redirect_target_safe("http://sub.example.com:80/", "example.com") is True

    def test_non_standard_ports_rejected_for_redirects(self):
        """Non-standard ports (8080, 8443, 22, 5432, 8000) must be rejected."""
        from asm.scan_common import is_redirect_target_safe

        assert is_redirect_target_safe("https://example.com:8443/login", "example.com") is False
        assert is_redirect_target_safe("http://example.com:8080/path", "example.com") is False
        assert is_redirect_target_safe("http://example.com:8000/", "example.com") is False
        assert is_redirect_target_safe("https://example.com:22/", "example.com") is False
        assert is_redirect_target_safe("http://example.com:5432/", "example.com") is False

    def test_non_http_schemes_and_invalid_urls_rejected(self):
        """Non-http(s) schemes and malformed URLs must be rejected."""
        from asm.scan_common import is_redirect_target_safe

        assert is_redirect_target_safe("ftp://example.com/file", "example.com") is False
        assert is_redirect_target_safe("javascript:alert(1)", "example.com") is False
        assert is_redirect_target_safe("data:text/html,test", "example.com") is False
        assert is_redirect_target_safe("gopher://example.com/", "example.com") is False
        assert is_redirect_target_safe("not-a-valid-url", "example.com") is False

    def test_out_of_scope_domains_rejected(self):
        """Redirects out of base_domain scope must be rejected."""
        from asm.scan_common import is_redirect_target_safe

        assert is_redirect_target_safe("https://evil.com/login", "example.com") is False
        assert is_redirect_target_safe("https://notexample.com/", "example.com") is False
        assert (
            is_redirect_target_safe("https://example.com.attacker.com/", "example.com")
            is False
        )

    def test_prober_and_headers_inspect_delegate_to_scan_common(self):
        """prober and headers_inspect must use is_redirect_target_safe."""
        from asm.headers_inspect import is_redirect_in_scope as headers_is_redirect_in_scope
        from asm.prober import is_redirect_in_scope as prober_is_redirect_in_scope

        # Standard ports pass
        assert headers_is_redirect_in_scope("https://sub.example.com/", "example.com") is True
        assert prober_is_redirect_in_scope("https://sub.example.com/", "example.com") is True

        # Non-standard ports fail in both
        assert (
            headers_is_redirect_in_scope("https://sub.example.com:8443/", "example.com")
            is False
        )
        assert (
            prober_is_redirect_in_scope("https://sub.example.com:8443/", "example.com")
            is False
        )


class TestForwardedAllowIpsLimitedToCaddy:
    """G6.2: uvicorn --forwarded-allow-ips is restricted to Caddy's exact IP."""

    def test_compose_prod_forwarded_allow_ips_strictly_caddy(self):
        """compose.prod.yml must assign static IP to Caddy and restrict api to that IP."""
        compose_path = REPO_ROOT / "compose.prod.yml"
        config = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        services = config["services"]

        # Caddy must have a static IP on app-tier
        caddy_svc = services["caddy"]
        assert "networks" in caddy_svc, "caddy service must define networks"
        app_tier_net = caddy_svc["networks"].get("app-tier", {})
        caddy_ip = app_tier_net.get("ipv4_address")
        assert caddy_ip == "10.89.0.20", (
            f"caddy must have static IP 10.89.0.20 on app-tier, found: {caddy_ip}"
        )

        # api command must set --forwarded-allow-ips to Caddy's exact IP
        api_svc = services["api"]
        command = api_svc.get("command", [])
        command_str = " ".join(command) if isinstance(command, list) else str(command)

        msg = f"api must restrict forwarded-allow-ips strictly to Caddy IP, found: {command_str}"
        assert (
            "--forwarded-allow-ips=10.89.0.20" in command_str
            or ("--forwarded-allow-ips" in command and "10.89.0.20" in command)
        ), msg

        # Must not be the entire subnet or wildcard
        assert "10.89.0.0/24" not in command_str, (
            "api --forwarded-allow-ips must NOT be the entire subnet 10.89.0.0/24"
        )
        assert "--forwarded-allow-ips=*" not in command_str


class TestEncryptedBackupScript:
    """G6.1: Encrypted backup script using age (public key only on host)."""

    def test_backup_encrypted_script_exists_and_executable(self):
        """scripts/backup_encrypted.sh must exist and be tracked as executable (100755)."""
        script_path = REPO_ROOT / "scripts/backup_encrypted.sh"
        assert script_path.is_file(), "scripts/backup_encrypted.sh must exist"

        listing = subprocess.run(
            ["git", "ls-files", "-s", "--", "scripts/backup_encrypted.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert listing, "scripts/backup_encrypted.sh must be tracked in git"
        mode = listing.split()[0]
        assert mode == "100755", (
            f"scripts/backup_encrypted.sh must be executable (100755), got {mode}"
        )

    def test_backup_encrypted_script_security_guards(self):
        """Script must enforce umask 077, require age public key, and reject private keys."""
        content = (REPO_ROOT / "scripts/backup_encrypted.sh").read_text(encoding="utf-8")
        assert "umask 077" in content, "Must enforce umask 077 (owner-only permissions)"
        assert "age" in content, "Must use age for encryption"
        assert ".sql.gz.age" in content, "Must output .sql.gz.age files"
        # Must prevent accidental private key usage as recipient
        assert "AGE-SECRET-KEY-" in content, "Must guard against secret key being used on host"

    def test_deploy_docs_document_age_backup_and_restore_procedure(self):
        """docs/DEPLOY.md must document age backup, public key isolation, and restore drill."""
        deploy_md = (REPO_ROOT / "docs/DEPLOY.md").read_text(encoding="utf-8")
        assert "backup_encrypted.sh" in deploy_md or "age" in deploy_md
        assert "age --decrypt" in deploy_md, "Must document age decryption restore procedure"
        assert "exposight_db_" in deploy_md
