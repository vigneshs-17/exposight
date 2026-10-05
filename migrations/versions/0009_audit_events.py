"""audit log events table and append-only trigger

Revision ID: 0009_audit_events
Revises: 0008_domain_verification
Create Date: 2026-10-02 03:00:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from asm.db.migration_guards import refuse_lossy_downgrade

# revision identifiers, used by Alembic.
revision: str = "0009_audit_events"
down_revision: str | None = "0008_domain_verification"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create audit_events table
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_audit_events_org_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'operator', 'system')",
            name="ck_audit_events_actor_type",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )

    # 2. Composite indexes
    op.create_index(
        "ix_audit_events_org_id_id",
        "audit_events",
        ["org_id", "id"],
    )
    op.create_index(
        "ix_audit_events_org_target",
        "audit_events",
        ["org_id", "target_type", "target_id"],
    )

    # 3. Append-only trigger
    op.execute("""
    CREATE OR REPLACE FUNCTION prevent_audit_events_tampering()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION
            'audit_events is append-only: updates, deletes, and truncates are prohibited';
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER trg_audit_events_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_audit_events_tampering();
    """)


def downgrade() -> None:
    # Dropping audit_events destroys the append-only audit history.
    refuse_lossy_downgrade(
        op.get_bind(),
        "SELECT count(*) FROM audit_events",
        "the audit log (audit_events)",
    )

    # 1. Drop trigger and function
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_events_tampering();")

    # 2. Drop indexes
    op.drop_index("ix_audit_events_org_target", table_name="audit_events")
    op.drop_index("ix_audit_events_org_id_id", table_name="audit_events")

    # 3. Drop table
    op.drop_table("audit_events")
