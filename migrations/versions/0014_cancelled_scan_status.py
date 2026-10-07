"""cancelled scan status

Revision ID: 0014_cancelled_scan_status
Revises: 0013_user_suspension
Create Date: 2026-10-06 22:30:00.000000+00:00

Data only. Before B-6, scans cancelled by account suspension or organization
deletion were stored as status 'failed' with a "Cancelled: ..." error. They now
use status 'cancelled' and a short neutral reason. Only the two exact old texts
are rewritten, so the downgrade restores them exactly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014_cancelled_scan_status"
down_revision: str | None = "0013_user_suspension"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (old error text, new error text); old status is 'failed', new status is 'cancelled'.
REWRITES = (
    (
        "Cancelled: every owner of this organization is suspended",
        "Scanning is paused for this organization.",
    ),
    ("Cancelled: organization deleted", "The organization was deleted."),
)

_SQL = sa.text(
    "UPDATE scan_runs SET status = :new_status, error = :new_error "
    "WHERE status = :old_status AND error = :old_error"
)


def upgrade() -> None:
    bind = op.get_bind()
    for old, new in REWRITES:
        bind.execute(
            _SQL,
            {"new_status": "cancelled", "new_error": new, "old_status": "failed", "old_error": old},
        )


def downgrade() -> None:
    bind = op.get_bind()
    for old, new in REWRITES:
        bind.execute(
            _SQL,
            {"new_status": "failed", "new_error": old, "old_status": "cancelled", "old_error": new},
        )
