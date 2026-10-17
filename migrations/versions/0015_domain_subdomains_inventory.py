"""domain subdomains persistent inventory

Revision ID: 0015_domain_subdomains_inventory
Revises: 0014_cancelled_scan_status
Create Date: 2026-10-17 10:00:00.000000+00:00

Creates the domain_subdomains table for bounded persistent discovery inventory tracking.
Tracks active/removed lifecycle, anchor source, and consecutive qualifying absences.
Foreign key references to scan_runs.id use ondelete='SET NULL' so scan retention does
not delete live inventory state or become blocked.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from asm.db.migration_guards import refuse_lossy_downgrade

# revision identifiers, used by Alembic.
revision: str = "0015_domain_subdomains_inventory"
down_revision: str | None = "0014_cancelled_scan_status"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_subdomains",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("subdomain", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="active", nullable=False),
        sa.Column("anchor_source", sa.String(length=64), server_default="crt.sh", nullable=False),
        sa.Column(
            "consecutive_qualifying_absences",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("first_seen_scan_run_id", sa.Integer(), nullable=True),
        sa.Column("last_seen_scan_run_id", sa.Integer(), nullable=True),
        sa.Column("last_qualifying_absence_scan_run_id", sa.Integer(), nullable=True),
        sa.Column("removed_at_scan_run_id", sa.Integer(), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=True),
        sa.Column("last_resolved", sa.Boolean(), nullable=True),
        sa.Column("last_applied_scan_run_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'removed')",
            name="ck_domain_subdomains_status",
        ),
        sa.CheckConstraint(
            "consecutive_qualifying_absences >= 0",
            name="ck_domain_subdomains_consecutive_absences",
        ),
        sa.ForeignKeyConstraint(
            ["domain_id"],
            ["domains.id"],
            name="fk_domain_subdomains_domain_id_domains",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["first_seen_scan_run_id"],
            ["scan_runs.id"],
            name="fk_domain_subdomains_first_seen_scan_run_id_scan_runs",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["last_seen_scan_run_id"],
            ["scan_runs.id"],
            name="fk_domain_subdomains_last_seen_scan_run_id_scan_runs",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["last_qualifying_absence_scan_run_id"],
            ["scan_runs.id"],
            name="fk_domain_subdomains_last_qa_scan_run_id_scan_runs",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["removed_at_scan_run_id"],
            ["scan_runs.id"],
            name="fk_domain_subdomains_removed_at_scan_run_id_scan_runs",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain_id",
            "subdomain",
            name="uq_domain_subdomains_domain_subdomain",
        ),
    )

    op.create_index(
        op.f("ix_domain_subdomains_domain_id"),
        "domain_subdomains",
        ["domain_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_domain_subdomains_subdomain"),
        "domain_subdomains",
        ["subdomain"],
        unique=False,
    )
    op.create_index(
        "ix_domain_subdomains_domain_status",
        "domain_subdomains",
        ["domain_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_domain_subdomains_domain_updated",
        "domain_subdomains",
        ["domain_id", "updated_at"],
        unique=False,
    )
    op.create_index(
        "ix_domain_subdomains_domain_applied",
        "domain_subdomains",
        ["domain_id", "last_applied_scan_run_id"],
        unique=False,
    )


def downgrade() -> None:
    refuse_lossy_downgrade(
        op.get_bind(),
        "SELECT count(*) FROM domain_subdomains",
        "persistent discovery inventory state (domain_subdomains)",
    )
    op.drop_index("ix_domain_subdomains_domain_applied", table_name="domain_subdomains")
    op.drop_index("ix_domain_subdomains_domain_updated", table_name="domain_subdomains")
    op.drop_index("ix_domain_subdomains_domain_status", table_name="domain_subdomains")
    op.drop_index(op.f("ix_domain_subdomains_subdomain"), table_name="domain_subdomains")
    op.drop_index(op.f("ix_domain_subdomains_domain_id"), table_name="domain_subdomains")
    op.drop_table("domain_subdomains")
