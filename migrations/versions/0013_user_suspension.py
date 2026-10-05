"""user suspension columns

Revision ID: 0013_user_suspension
Revises: 0012_scan_runs_domain_index
Create Date: 2026-10-05 21:00:00.000000+00:00

Additive: two nullable columns on users.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from asm.db.migration_guards import refuse_lossy_downgrade

# revision identifiers, used by Alembic.
revision: str = "0013_user_suspension"
down_revision: str | None = "0012_scan_runs_domain_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("suspended_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    # Dropping the columns would silently unsuspend every suspended account.
    refuse_lossy_downgrade(
        op.get_bind(),
        "SELECT count(*) FROM users WHERE suspended_at IS NOT NULL",
        "account suspensions (suspended accounts would regain access)",
    )
    op.drop_column("users", "suspended_reason")
    op.drop_column("users", "suspended_at")
