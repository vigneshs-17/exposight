"""tenant isolation

Revision ID: 0007_tenant_isolation
Revises: 0006_users_organizations_roles
Create Date: 2026-10-01 11:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from asm.db.migration_guards import refuse_lossy_downgrade

# revision identifiers, used by Alembic.
revision: str = "0007_tenant_isolation"
down_revision: str | None = "0006_users_organizations_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add system_kind column and index to organizations
    op.add_column("organizations", sa.Column("system_kind", sa.String(length=64), nullable=True))
    op.create_index("ix_organizations_system_kind", "organizations", ["system_kind"], unique=False)

    conn = op.get_bind()
    has_domains = conn.execute(sa.text("SELECT 1 FROM domains LIMIT 1")).fetchone() is not None

    if has_domains:
        # Always create a dedicated quarantine organization with system_kind = 'legacy_quarantine'
        # Bound parameters used strictly - no f-strings
        legacy_org_id = conn.execute(
            sa.text(
                "INSERT INTO organizations (name, system_kind, created_at) "
                "VALUES (:name, :kind, now()) RETURNING id"
            ),
            {"name": "Legacy Quarantine", "kind": "legacy_quarantine"},
        ).scalar_one()

        # Add org_id as nullable first to allow backfill
        op.add_column("domains", sa.Column("org_id", sa.Integer(), nullable=True))

        # Safe backfill: quarantine all existing domains under Legacy Quarantine org
        conn.execute(
            sa.text("UPDATE domains SET org_id = :org_id WHERE org_id IS NULL"),
            {"org_id": legacy_org_id},
        )

        # Enforce NOT NULL on org_id
        op.alter_column("domains", "org_id", nullable=False)
    else:
        op.add_column("domains", sa.Column("org_id", sa.Integer(), nullable=False))

    # 2. Add Foreign Key and Index on domains.org_id
    op.create_foreign_key(
        "fk_domains_org_id_organizations",
        "domains",
        "organizations",
        ["org_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_domains_org_id", "domains", ["org_id"], unique=False)

    # 3. Replace global unique constraint on domain name with per-org unique constraint
    op.drop_index("ix_domains_name", table_name="domains")
    op.create_unique_constraint("uq_domains_org_id_name", "domains", ["org_id", "name"])
    op.create_index("ix_domains_name", "domains", ["name"], unique=False)


def downgrade() -> None:
    # Dropping domains.org_id loses which organization owns each domain.
    refuse_lossy_downgrade(
        op.get_bind(),
        "SELECT count(*) FROM domains",
        "the organization that owns each domain (domains.org_id)",
    )

    # 1. Drop per-org unique constraint and re-create global unique index
    op.drop_index("ix_domains_name", table_name="domains")
    op.drop_constraint("uq_domains_org_id_name", "domains", type_="unique")
    op.create_index("ix_domains_name", "domains", ["name"], unique=True)

    # 2. Drop foreign key, index and org_id column from domains
    op.drop_constraint("fk_domains_org_id_organizations", "domains", type_="foreignkey")
    op.drop_index("ix_domains_org_id", table_name="domains")
    op.drop_column("domains", "org_id")

    # 3. Delete ONLY the organization with system_kind = 'legacy_quarantine'
    # Any customer organization named 'Legacy' or similar is completely untouched
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM organizations WHERE system_kind = :kind"),
        {"kind": "legacy_quarantine"},
    )

    # 4. Drop index and system_kind column from organizations
    op.drop_index("ix_organizations_system_kind", table_name="organizations")
    op.drop_column("organizations", "system_kind")
