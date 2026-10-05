"""Least-privilege PostgreSQL grants for the application role (v3.6b A1).

Two database roles are used in production:

- the owner role runs Alembic migrations and owns every table, sequence and
  trigger. Only the owner can ALTER or DROP them (including disabling the
  audit_events append-only trigger).
- the app role is used by the API and the worker. It owns nothing and gets
  only the data privileges it needs. On audit_events it may only INSERT and
  SELECT, so it can neither change history nor disable the trigger.

The same SQL is run by migration 0010 and by the database tests, so the tests
prove exactly what production gets.
"""

import re

DEFAULT_APP_ROLE = "exposight_app"
DEFAULT_OWNER_ROLE = "exposight_owner"

# Role names are interpolated into SQL as identifiers, so only plain names are allowed.
_ROLE_NAME_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def validate_role_name(role: str) -> str:
    """Return role if it is a plain lowercase PostgreSQL identifier, else raise ValueError."""
    if not _ROLE_NAME_RE.fullmatch(role):
        raise ValueError(f"Invalid PostgreSQL role name: {role!r}")
    return role


def app_role_grant_statements(app_role: str) -> list[str]:
    """Return the GRANT statements for the app role, to run as the owner role.

    ALTER DEFAULT PRIVILEGES uses FOR ROLE CURRENT_USER: tables and sequences
    that the owner (the role running this) creates later get the same grants,
    so a future migration cannot silently leave the app without access.
    """
    role = validate_role_name(app_role)
    return [
        f"GRANT USAGE ON SCHEMA public TO {role}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}",
        # Append-only audit log: the app may write and read, never change history.
        f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {role}",
        "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}",
        "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public "
        f"GRANT USAGE, SELECT ON SEQUENCES TO {role}",
    ]


def app_role_revoke_statements(app_role: str) -> list[str]:
    """Return statements that undo app_role_grant_statements (migration downgrade)."""
    role = validate_role_name(app_role)
    return [
        "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public "
        f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {role}",
        "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public "
        f"REVOKE USAGE, SELECT ON SEQUENCES FROM {role}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}",
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}",
        f"REVOKE USAGE ON SCHEMA public FROM {role}",
    ]


def transfer_ownership_statements(owner_role: str) -> list[str]:
    """Return statements that move every table and function in schema public to owner_role.

    Used by the existing-volume runbook in docs/DEPLOY.md, run as the superuser.
    REASSIGN OWNED cannot be used there: it refuses to touch objects of the
    bootstrap superuser. Sequences owned by a table move with the table.
    """
    role = validate_role_name(owner_role)
    return [
        "DO $$ DECLARE r record; BEGIN "
        "FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP "
        f"EXECUTE format('ALTER TABLE public.%I OWNER TO {role}', r.tablename); "
        "END LOOP; "
        "FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' LOOP "
        f"EXECUTE format('ALTER FUNCTION %s OWNER TO {role}', r.fn); "
        "END LOOP; END $$",
    ]
