"""v3.6b A1: the least-privilege app role cannot alter or bypass the append-only audit log.

Runs the exact grant SQL that migration 0010 runs, against a throwaway role created
inside a transaction that is always rolled back (CREATE ROLE is transactional).
"""

import uuid
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from asm.audit import record_event
from asm.db.models import Domain, Organization
from asm.db.roles import (
    DEFAULT_APP_ROLE,
    DEFAULT_OWNER_ROLE,
    app_role_grant_statements,
    app_role_revoke_statements,
    transfer_ownership_statements,
    validate_role_name,
)

pytestmark = pytest.mark.db

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def app_role_conn(db_engine):
    """Yield (connection, role) with a fresh grant-only app role; everything is rolled back."""
    conn = db_engine.connect()
    trans = conn.begin()
    can_create = conn.execute(
        text("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user")
    ).scalar()
    if not can_create:
        trans.rollback()
        conn.close()
        pytest.fail("TEST_DATABASE_URL user needs CREATEROLE (or superuser) for role tests")

    role = f"exposight_app_t{uuid.uuid4().hex[:12]}"
    conn.execute(text(f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOINHERIT"))
    conn.execute(text(f"GRANT {role} TO current_user"))  # allows SET ROLE without superuser
    for statement in app_role_grant_statements(role):
        conn.execute(text(statement))
    try:
        yield conn, role
    finally:
        trans.rollback()
        conn.close()


def _expect_insufficient_privilege(conn, sql: str, params: dict | None = None) -> None:
    """Run sql in a savepoint and assert PostgreSQL refuses it with SQLSTATE 42501."""
    savepoint = conn.begin_nested()
    with pytest.raises(DBAPIError) as excinfo:
        conn.execute(text(sql), params or {})
    savepoint.rollback()
    assert isinstance(excinfo.value.orig, psycopg.errors.InsufficientPrivilege), excinfo.value


def _as_app(conn, role: str) -> None:
    conn.execute(text(f"SET LOCAL ROLE {role}"))


def test_app_role_writes_data_and_appends_audit_events(app_role_conn):
    conn, role = app_role_conn
    _as_app(conn, role)
    session = Session(bind=conn, join_transaction_mode="create_savepoint")

    org = Organization(name="Role Test Org")  # needs sequence USAGE
    session.add(org)
    session.flush()
    domain = Domain(org_id=org.id, name="role-test.example.com")
    session.add(domain)
    session.flush()
    domain.alerts_enabled = False  # UPDATE on an ordinary table
    record_event(
        session,
        org_id=org.id,
        actor_type="system",
        action="domain.created",
        target_type="domain",
        target_id=str(domain.id),
        metadata={"name": domain.name},
    )
    session.flush()
    session.delete(domain)  # DELETE on an ordinary table
    session.flush()

    count = conn.execute(
        text("SELECT count(*) FROM audit_events WHERE org_id = :o"), {"o": org.id}
    ).scalar()
    assert count == 1
    assert conn.execute(text("SELECT current_user")).scalar() == role


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'scan.queued'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only",
        "ALTER TABLE audit_events DISABLE TRIGGER ALL",
        "DROP TRIGGER trg_audit_events_append_only ON audit_events",
        "DROP TABLE audit_events",
        "ALTER TABLE domains ADD COLUMN evil text",
        "CREATE TABLE app_owned_table (id int)",
    ],
)
def test_app_role_cannot_tamper_with_audit_log_or_schema(app_role_conn, statement):
    conn, role = app_role_conn
    _as_app(conn, role)
    _expect_insufficient_privilege(conn, statement)


def test_app_role_owns_nothing(app_role_conn):
    conn, role = app_role_conn
    owned = conn.execute(
        text(
            """
            SELECT
              (SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
                 WHERE r.rolname = :role)
            + (SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
                 WHERE r.rolname = :role)
            + (SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
                 WHERE r.rolname = :role)
            """
        ),
        {"role": role},
    ).scalar()
    assert owned == 0


def test_tables_created_later_by_owner_are_granted_by_default(app_role_conn):
    """ALTER DEFAULT PRIVILEGES FOR ROLE <owner>: a future migration's table is usable."""
    conn, role = app_role_conn
    table = f"future_{uuid.uuid4().hex[:8]}"
    conn.execute(text(f"CREATE TABLE {table} (id serial PRIMARY KEY, v text)"))  # as owner
    _as_app(conn, role)
    conn.execute(text(f"INSERT INTO {table} (v) VALUES ('x')"))
    assert conn.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 1
    _expect_insufficient_privilege(conn, f"ALTER TABLE {table} ADD COLUMN w text")


def test_revoke_statements_remove_access(app_role_conn):
    conn, role = app_role_conn
    for statement in app_role_revoke_statements(role):
        conn.execute(text(statement))
    _as_app(conn, role)
    _expect_insufficient_privilege(conn, "SELECT 1 FROM domains LIMIT 1")


@pytest.mark.parametrize("bad", ["", "Exposight", "app; DROP TABLE x", "a" * 64, "1app"])
def test_role_names_are_validated_before_sql(bad):
    with pytest.raises(ValueError):
        validate_role_name(bad)


def test_existing_volume_runbook_flow(db_engine):
    """Runbook path: superuser moves ownership to a non-superuser owner, owner grants the app."""
    conn = db_engine.connect()
    trans = conn.begin()
    try:
        suffix = uuid.uuid4().hex[:10]
        owner, app = f"exposight_owner_t{suffix}", f"exposight_app_t{suffix}"
        conn.execute(text(f"CREATE ROLE {owner} NOLOGIN NOSUPERUSER"))
        conn.execute(text(f"CREATE ROLE {app} NOLOGIN NOSUPERUSER NOINHERIT"))
        conn.execute(text(f"GRANT {owner}, {app} TO current_user"))
        for statement in transfer_ownership_statements(owner):
            conn.execute(text(statement))
        table_owner = conn.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'audit_events'")
        ).scalar()
        assert table_owner == owner

        conn.execute(text(f"SET LOCAL ROLE {owner}"))
        for statement in app_role_grant_statements(app):
            conn.execute(text(statement))

        conn.execute(text(f"SET LOCAL ROLE {app}"))
        conn.execute(text("SELECT count(*) FROM domains")).scalar()
        _expect_insufficient_privilege(
            conn, "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only"
        )

        # The owner (and only the owner) can still manage the trigger.
        conn.execute(text(f"SET LOCAL ROLE {owner}"))
        savepoint = conn.begin_nested()
        conn.execute(
            text("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only")
        )
        savepoint.rollback()
    finally:
        trans.rollback()
        conn.close()


def test_deploy_runbook_lists_the_exact_grant_sql():
    """docs/DEPLOY.md's existing-volume runbook must stay identical to the tested SQL."""
    deploy = (REPO_ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    statements = app_role_grant_statements(DEFAULT_APP_ROLE) + transfer_ownership_statements(
        DEFAULT_OWNER_ROLE
    )
    for statement in statements:
        assert f"{statement};" in deploy, f"DEPLOY.md runbook is missing: {statement}"


def test_init_script_creates_non_superuser_roles():
    script = (REPO_ROOT / "deploy" / "postgres-init" / "10-roles.sh").read_text(encoding="utf-8")
    assert "\r" not in script, "init script must use LF line endings"
    assert 'CREATE ROLE :"app_user" LOGIN NOSUPERUSER' in script
    assert 'CREATE ROLE :"owner_user" LOGIN NOSUPERUSER' in script
    assert "NOINHERIT" in script
    assert 'ALTER DATABASE :"db_name" OWNER TO :"owner_user"' in script
    assert "set -euo pipefail" in script
