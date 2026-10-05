"""least-privilege grants for the application database role

Revision ID: 0010_app_role_grants
Revises: 0009_audit_events
Create Date: 2026-10-05 12:00:00.000000+00:00

Grants only; no schema or data change. Runs as the owner role (the role that
runs Alembic). The app role itself is created by deploy/postgres-init on a
fresh volume, or by the manual runbook in docs/DEPLOY.md.
"""

import os
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

from asm.config import is_production
from asm.db.roles import (
    DEFAULT_APP_ROLE,
    app_role_grant_statements,
    app_role_revoke_statements,
    validate_role_name,
)

# revision identifiers, used by Alembic.
revision: str = "0010_app_role_grants"
down_revision: str | None = "0009_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _app_role() -> str:
    return validate_role_name(os.getenv("APP_DB_USER", "").strip() or DEFAULT_APP_ROLE)


def _role_exists(role: str) -> bool:
    bind = op.get_bind()
    return bool(
        bind.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
    )


def upgrade() -> None:
    role = _app_role()
    if not _role_exists(role):
        if is_production():
            raise RuntimeError(
                f"App database role '{role}' does not exist; create it before migrating "
                "(see docs/DEPLOY.md, 'Least-privilege database roles')"
            )
        # Development databases may use one role for everything; nothing to grant.
        return
    for statement in app_role_grant_statements(role):
        op.execute(statement)


def downgrade() -> None:
    role = _app_role()
    if not _role_exists(role):
        return
    for statement in app_role_revoke_statements(role):
        op.execute(statement)
