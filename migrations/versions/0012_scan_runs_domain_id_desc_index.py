"""index scan_runs (domain_id, id DESC)

Revision ID: 0012_scan_runs_domain_index
Revises: 0011_org_invites
Create Date: 2026-10-05 18:00:00.000000+00:00

Additive index only.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012_scan_runs_domain_index"
down_revision: str | None = "0011_org_invites"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_scan_runs_domain_id_id_desc",
        "scan_runs",
        ["domain_id", sa.text("id DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_runs_domain_id_id_desc", table_name="scan_runs")
