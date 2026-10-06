"""Static configuration and structure tests for production deployment artifacts."""

from __future__ import annotations

import re
from pathlib import Path

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
    assert services["caddy"]["image"] == "caddy:2.11.4-alpine"


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

    # Forwarded allow ips check
    assert "--forwarded-allow-ips" in command_str, "api must specify --forwarded-allow-ips"
    assert "--forwarded-allow-ips=*" not in command_str, (
        "api --forwarded-allow-ips must NOT be wildcard '*'"
    )
    assert "10.89.0.0/24" in command_str, "api --forwarded-allow-ips must match the app-tier subnet"

    # Caddy depends on api being healthy
    caddy_svc = config["services"]["caddy"]
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
    """Caddyfile proxies {$DOMAIN} to api:8000, adds only HSTS, and never touches CSP."""
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
    # HSTS is the only header directive Caddy is allowed to set.
    header_lines = [
        ln.strip() for ln in lower_content.splitlines() if ln.strip().startswith("header ")
    ]
    assert len(header_lines) == 1, f"Caddy must only add HSTS, found: {header_lines}"


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
