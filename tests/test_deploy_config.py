"""Static configuration and structure tests for production deployment artifacts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compose_prod_structure_and_ports():
    """compose.prod.yml must parse, publish no DB/API/worker ports, and expose only Caddy."""
    compose_path = REPO_ROOT / "compose.prod.yml"
    assert compose_path.is_file(), "compose.prod.yml must exist"

    raw_content = compose_path.read_text(encoding="utf-8")
    config = yaml.safe_load(raw_content)

    assert "services" in config, "compose.prod.yml must define services"
    services = config["services"]

    # Ensure required production services exist
    for required_service in ["db", "migrate", "api", "worker", "caddy"]:
        assert required_service in services, (
            f"Missing {required_service} service in compose.prod.yml"
        )

    # db, migrate, api, worker must not publish ANY ports to host
    for internal_svc in ["db", "migrate", "api", "worker"]:
        svc_config = services[internal_svc]
        assert "ports" not in svc_config or not svc_config["ports"], (
            f"Service '{internal_svc}' must not publish ports to host, "
            f"found: {svc_config.get('ports')}"
        )

    # Only caddy publishes 80 and 443
    caddy_svc = services["caddy"]
    assert "ports" in caddy_svc, "caddy service must publish ports"
    published_ports = [str(p) for p in caddy_svc["ports"]]
    assert "80:80" in published_ports, f"caddy must publish port 80:80, found: {published_ports}"
    assert "443:443" in published_ports, (
        f"caddy must publish port 443:443, found: {published_ports}"
    )
    assert len(published_ports) == 2, (
        f"caddy should only publish 80 and 443, found: {published_ports}"
    )

    # Database image must be pinned
    assert services["db"]["image"] == "postgres:18.6-alpine"
    # Caddy image must be pinned
    assert services["caddy"]["image"] == "caddy:2.11.7-alpine"


def test_compose_prod_api_healthcheck_and_proxy_headers():
    """API service must have a healthcheck and restricted forwarded-allow-ips (not wildcard '*')."""
    compose_path = REPO_ROOT / "compose.prod.yml"
    raw_content = compose_path.read_text(encoding="utf-8")
    config = yaml.safe_load(raw_content)
    api_svc = config["services"]["api"]

    # Healthcheck verification
    assert "healthcheck" in api_svc, "api service must define a healthcheck"
    healthcheck = api_svc["healthcheck"]
    test_cmd = healthcheck.get("test", [])
    test_str = " ".join(test_cmd) if isinstance(test_cmd, list) else str(test_cmd)
    assert "/health" in test_str, f"api healthcheck must verify /health endpoint, found: {test_str}"

    # Command verification for proxy headers & single worker
    command = api_svc.get("command", [])
    command_str = " ".join(command) if isinstance(command, list) else str(command)

    assert "--workers 1" in command_str or ("--workers" in command and "1" in command), (
        "api uvicorn must run with --workers 1 for in-memory rate limiting"
    )
    assert "--proxy-headers" in command_str, "api must include --proxy-headers"

    # Forwarded allow ips check: must be strictly Caddy's fixed IP (10.89.0.20)
    assert "--forwarded-allow-ips" in command_str, "api must specify --forwarded-allow-ips"
    assert "--forwarded-allow-ips=*" not in command_str, (
        "api --forwarded-allow-ips must NOT be wildcard '*'"
    )
    assert "10.89.0.20" in command_str, (
        "api --forwarded-allow-ips must strictly match Caddy's IP 10.89.0.20"
    )
    assert "10.89.0.0/24" not in command_str, (
        "api --forwarded-allow-ips must not be the entire subnet"
    )

    # Caddy depends on api being healthy and has fixed IP 10.89.0.20
    caddy_svc = config["services"]["caddy"]
    assert caddy_svc["networks"]["app-tier"]["ipv4_address"] == "10.89.0.20"
    depends_on = caddy_svc.get("depends_on", {})
    assert "api" in depends_on, "caddy must depend on api"
    assert depends_on["api"].get("condition") == "service_healthy", (
        "caddy must depend on api with condition: service_healthy"
    )


def test_env_production_example_variables_and_no_secrets():
    """.env.production.example must list config vars with placeholder values and no secrets."""
    env_path = REPO_ROOT / ".env.production.example"
    assert env_path.is_file(), ".env.production.example must exist"

    content = env_path.read_text(encoding="utf-8")
    lines = [
        line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")
    ]

    env_dict: dict[str, str] = {}
    for line in lines:
        if "=" in line:
            key, val = line.split("=", 1)
            env_dict[key.strip()] = val.strip()

    required_vars = [
        "ENVIRONMENT",
        "DOMAIN",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "DATABASE_URL",
        "SUPABASE_URL",
        "SUPABASE_PUBLISHABLE_KEY",
        "JWT_AUDIENCE",
        "CERTSPOTTER_API_KEY",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_FROM",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_STARTTLS",
        "SMTP_SSL",
        "OWNER_DB_USER",
        "OWNER_DB_PASSWORD",
        "MIGRATION_DATABASE_URL",
        "APP_DB_USER",
        "APP_DB_PASSWORD",
    ]

    for var in required_vars:
        assert var in env_dict, f".env.production.example is missing variable: {var}"

    assert env_dict["ENVIRONMENT"] == "production"

    # Secrets checks: no real Supabase secret service keys or real password values
    assert not env_dict["SUPABASE_PUBLISHABLE_KEY"].startswith("sb_secret_"), (
        "SUPABASE_PUBLISHABLE_KEY must not contain a secret service key"
    )
    assert not env_dict["SUPABASE_PUBLISHABLE_KEY"].startswith("eyJ"), (
        "SUPABASE_PUBLISHABLE_KEY must be a placeholder, not a real JWT"
    )

    # Database credentials must be placeholders
    assert "CHANGE_ME" in env_dict["POSTGRES_PASSWORD"]
    assert "CHANGE_ME" in env_dict["DATABASE_URL"]

    # Verify no private API keys or real IP addresses
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for key, val in env_dict.items():
        if val:
            assert not ip_pattern.search(val), (
                f"Variable {key} appears to contain a real IP address: {val}"
            )


def test_caddyfile_content_invariants():
    """Caddyfile proxies {$DOMAIN} to api:8000, adds only HSTS, drops Server, never touches CSP."""
    caddyfile_path = REPO_ROOT / "Caddyfile"
    assert caddyfile_path.is_file(), "Caddyfile must exist"

    content = caddyfile_path.read_text(encoding="utf-8")
    assert "{$DOMAIN}" in content
    assert "reverse_proxy api:8000" in content

    # The app sets CSP itself, so Caddy must never set or override it.
    lower_content = content.lower()
    assert "content-security-policy" not in lower_content
    # The app does NOT set HSTS, so Caddy (the HTTPS edge) must add it.
    assert 'header strict-transport-security "max-age=31536000"' in lower_content
    # Caddy only adds HSTS and removes Server (H-Hdr-1) and Via (IC-1, F10): Server on the
    # HTTP redirect site, then HSTS, Server and Via on the HTTPS site. Nothing else.
    header_lines = [
        ln.strip() for ln in lower_content.splitlines() if ln.strip().startswith("header ")
    ]
    assert header_lines == [
        "header -server",
        'header strict-transport-security "max-age=31536000"',
        "header -server",
        "header -via",
    ], f"Caddy must only add HSTS and drop Server/Via, found: {header_lines}"


def test_compose_prod_least_privilege_database_roles():
    """migrate runs as the owner role; api and worker use the app role; init script mounted."""
    config = yaml.safe_load((REPO_ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
    services = config["services"]

    assert "./deploy/postgres-init:/docker-entrypoint-initdb.d:ro" in services["db"]["volumes"]
    for var in ("OWNER_DB_USER", "OWNER_DB_PASSWORD", "APP_DB_USER", "APP_DB_PASSWORD"):
        assert var in services["db"]["environment"], f"db service is missing {var}"

    assert services["migrate"]["environment"]["DATABASE_URL"] == "${MIGRATION_DATABASE_URL}"
    for svc in ("api", "worker"):
        assert services[svc]["environment"]["DATABASE_URL"] == "${DATABASE_URL}"

    env = (REPO_ROOT / ".env.production.example").read_text(encoding="utf-8")
    database_url = next(
        line.split("=", 1)[1] for line in env.splitlines() if line.startswith("DATABASE_URL=")
    )
    assert database_url.startswith("postgresql+psycopg://exposight_app:"), (
        "api/worker DATABASE_URL must use the least-privilege app role, never the superuser"
    )
    migration_url = next(
        line.split("=", 1)[1]
        for line in env.splitlines()
        if line.startswith("MIGRATION_DATABASE_URL=")
    )
    assert migration_url.startswith("postgresql+psycopg://exposight_owner:")


def test_retention_purge_is_off_by_default_in_production_config():
    """v3.6c B-5 (D9): the worker gets the switch, and it defaults to off."""
    config = yaml.safe_load((REPO_ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
    worker_env = config["services"]["worker"]["environment"]
    assert worker_env["RETENTION_PURGE_ENABLED"] == "${RETENTION_PURGE_ENABLED:-false}"
    example = (REPO_ROOT / ".env.production.example").read_text(encoding="utf-8")
    assert "RETENTION_PURGE_ENABLED=false" in example.splitlines()


def _env_default(compose_file: str, service: str, var: str) -> object:
    """Parsed `${VAR:-default}` default of one service's environment entry."""
    config = yaml.safe_load((REPO_ROOT / compose_file).read_text(encoding="utf-8"))
    value = config["services"][service]["environment"][var]
    prefix = "${" + var + ":-"
    assert value.startswith(prefix) and value.endswith("}"), value
    return yaml.safe_load(value[len(prefix) : -1])


@pytest.mark.parametrize("compose_file", ["compose.prod.yml", "docker-compose.yml"])
def test_verification_resolvers_passed_to_api_and_worker_with_app_default(compose_file):
    """E-4: both processes run the DNS check; unset falls back to the Settings default."""
    from asm.config import Settings

    app_default = Settings.model_fields["verification_resolvers"].default
    for svc in ("api", "worker"):
        assert _env_default(compose_file, svc, "VERIFICATION_RESOLVERS") == app_default


@pytest.mark.parametrize("compose_file", ["compose.prod.yml", "docker-compose.yml"])
def test_org_creation_allowlist_passed_to_api_with_app_default(compose_file):
    """H-Auth-1: the api enforces it; unset falls back to the Settings default (nobody)."""
    from asm.config import Settings

    app_default = Settings.model_fields["org_creation_allowed_emails"].default
    assert _env_default(compose_file, "api", "ORG_CREATION_ALLOWED_EMAILS") == app_default == []


def test_env_production_example_lists_org_creation_allowlist():
    example = (REPO_ROOT / ".env.production.example").read_text(encoding="utf-8")
    assert any(line.startswith("ORG_CREATION_ALLOWED_EMAILS=") for line in example.splitlines())


# --- v3.6c D-2: worker egress firewall ---------------------------------------------------


def _prod_services() -> dict:
    return yaml.safe_load((REPO_ROOT / "compose.prod.yml").read_text(encoding="utf-8"))[
        "services"
    ]


def test_worker_shares_the_egress_namespace_without_net_admin():
    """The worker joins egress's network namespace and cannot change its rules."""
    services = _prod_services()
    worker, egress = services["worker"], services["egress"]
    assert worker["network_mode"] == "service:egress"
    assert "networks" not in worker
    assert "cap_add" not in worker and "privileged" not in worker
    assert worker["depends_on"]["egress"] == {"condition": "service_healthy", "restart": True}
    assert "NET_ADMIN" in egress["cap_add"] and egress["cap_drop"] == ["ALL"]
    assert "ports" not in egress
    assert egress["dns"] == ["1.1.1.1", "9.9.9.9"]  # D14
    for name, svc in services.items():
        if name != "egress":
            assert "NET_ADMIN" not in svc.get("cap_add", []), name


def test_postgres_allow_rule_is_the_db_static_ip_only():
    """Correction 2026-10-07: 5432 is allowed to the db's fixed IP, never a range."""
    import ipaddress

    config = yaml.safe_load((REPO_ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
    db_ip = config["services"]["db"]["networks"]["app-tier"]["ipv4_address"]
    assert config["services"]["egress"]["environment"]["EGRESS_DB_IP"] == db_ip
    ipam = config["networks"]["app-tier"]["ipam"]["config"][0]
    assert ipaddress.ip_address(db_ip) in ipaddress.ip_network(ipam["subnet"])
    # Dynamic addresses come from ip_range, so nothing else can take the db's IP.
    assert ipaddress.ip_address(db_ip) not in ipaddress.ip_network(ipam["ip_range"])

    rules = (REPO_ROOT / "deploy/egress/rules.sh").read_text(encoding="utf-8")
    accept_5432 = [line for line in rules.splitlines() if "5432" in line and "ACCEPT" in line]
    assert accept_5432 == ['iptables -A OUTPUT -p tcp -d "$DB_IP" --dport 5432 -j ACCEPT']


def test_egress_rules_block_internal_ranges_and_fail_closed():
    rules = (REPO_ROOT / "deploy/egress/rules.sh").read_text(encoding="utf-8")
    assert "set -eu" in rules.splitlines()
    for net in (
        "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16",
    ):
        assert net in rules, net
    # Azure WireServer / platform DNS: public-looking, so no range above covers it.
    assert (
        "iptables -A OUTPUT -d 168.63.129.16/32 -j REJECT --reject-with icmp-admin-prohibited"
        in rules.splitlines()
    )
    assert "ip6tables -P OUTPUT DROP" in rules  # D12
    # The readiness marker is written only after every rule was applied.
    assert rules.rindex("touch /run/egress-ready") > rules.rindex("ip6tables -P OUTPUT DROP")
    health = " ".join(_prod_services()["egress"]["healthcheck"]["test"])
    assert "/run/egress-ready" in health and "169.254.0.0/16" in health


def _load_egress_check():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "egress_check", REPO_ROOT / "scripts/egress_check.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_egress_check_covers_the_required_targets():
    expected = {(host, port): want for _, host, port, want in _load_egress_check().targets()}
    assert expected[("db", 5432)] == "CONNECTED"
    assert expected[("api", 8000)] == "BLOCKED"
    assert expected[("api", 5432)] == "BLOCKED"  # another private IP on 5432
    assert expected[("169.254.169.254", 80)] == "BLOCKED"
    assert expected[("168.63.129.16", 80)] == "BLOCKED"  # Azure WireServer


def test_egress_check_does_not_count_a_closed_port_as_blocked():
    """A refused connect also happens without any firewall, so it must not pass."""
    import socket

    check = _load_egress_check()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]  # bound, not listening: connects are refused
        outcome, _ = check.probe("127.0.0.1", port)
    assert outcome == "REFUSED"


def test_every_service_has_log_rotation():
    """Phase E: json-file logs are capped for every service (Caddy access logs stay off)."""
    services = _prod_services()
    assert services, "compose.prod.yml has no services"
    for name, svc in services.items():
        logging_cfg = svc.get("logging") or {}
        assert logging_cfg.get("driver") == "json-file", name
        options = logging_cfg.get("options") or {}
        assert options.get("max-size") == "10m", name
        assert options.get("max-file") == "3", name


def test_shell_scripts_are_executable_in_git():
    """Cron runs scripts/*.sh directly; a 100644 index mode gives "Permission denied" on the VM."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    listing = subprocess.run(
        ["git", "ls-files", "-s", "--", "scripts/*.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    modes = {line.split("\t", 1)[1]: line.split()[0] for line in listing}
    assert "scripts/backup_db.sh" in modes, "scripts/backup_db.sh must be tracked"
    assert "scripts/backup_encrypted.sh" in modes, "scripts/backup_encrypted.sh must be tracked"
    not_executable = {path: mode for path, mode in modes.items() if mode != "100755"}
    assert not not_executable, f"run git update-index --chmod=+x on: {not_executable}"


def test_compose_staging_override_structure():
    """compose.staging.override.yml must define project name, tags, and mailpit pin."""
    override_path = REPO_ROOT / "compose.staging.override.yml"
    assert override_path.is_file(), "compose.staging.override.yml must exist"

    raw_content = override_path.read_text(encoding="utf-8")
    config = yaml.safe_load(raw_content)

    assert config.get("name") == "exposight-staging"
    services = config.get("services", {})
    assert "migrate" in services
    assert "api" in services
    assert "egress" in services
    assert "worker" in services
    assert "mailsink" in services

    # Worker forwards discovery resource limits
    worker_env = services["worker"].get("environment", {})
    assert "DISCOVERY_MAX_RESPONSE_BYTES" in worker_env
    assert "DISCOVERY_MAX_HOSTS" in worker_env

    # Mailsink service
    mailsink = services["mailsink"]
    assert mailsink.get("profiles") == ["mailsink"]
    assert mailsink.get("image") == "axllent/mailpit:v1.31.5"
    assert mailsink.get("network_mode") == "service:egress"

