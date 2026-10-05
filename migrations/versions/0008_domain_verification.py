"""domain verification via DNS TXT and operator override

Revision ID: 0008_domain_verification
Revises: 0007_tenant_isolation
Create Date: 2026-10-01 18:00:00.000000+00:00

"""

import secrets
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from asm.db.migration_guards import refuse_lossy_downgrade

# revision identifiers, used by Alembic.
revision: str = "0008_domain_verification"
down_revision: str | None = "0007_tenant_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add verification state columns to domains
    op.add_column(
        "domains",
        sa.Column(
            "verification_status",
            sa.String(length=32),
            server_default="pending",
            nullable=False,
        ),
    )
    op.add_column(
        "domains",
        sa.Column("verification_token", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "domains",
        sa.Column(
            "verification_method",
            sa.String(length=32),
            server_default="dns_txt",
            nullable=False,
        ),
    )
    op.add_column(
        "domains",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "domains",
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "domains",
        sa.Column(
            "consecutive_misses",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "domains",
        sa.Column("verification_reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "domains",
        sa.Column("verification_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "domains",
        sa.Column("next_reverification_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. Backfill verification_token with cryptographically secure random token for existing domains
    conn = op.get_bind()
    domain_rows = conn.execute(sa.text("SELECT id FROM domains")).fetchall()
    for row in domain_rows:
        dom_id = row[0]
        token = secrets.token_urlsafe(32)
        conn.execute(
            sa.text("UPDATE domains SET verification_token = :token WHERE id = :id"),
            {"token": token, "id": dom_id},
        )

    # Enforce NOT NULL on verification_token
    op.alter_column("domains", "verification_token", nullable=False)

    # 3. Existing domains become pending (no domain keeps scan rights without proof)
    conn.execute(
        sa.text(
            "UPDATE domains SET verification_status = 'pending', verified_at = NULL, "
            "consecutive_misses = 0, next_reverification_at = NULL"
        )
    )

    # 4. Make alert_notifications.scan_run_id nullable to support domain-level outbox alerts
    op.alter_column("alert_notifications", "scan_run_id", nullable=True)

    # 5. Check constraints on domains
    op.create_check_constraint(
        "ck_domains_verification_status",
        "domains",
        "verification_status IN ('pending', 'verified', 'lapsed')",
    )
    op.create_check_constraint(
        "ck_domains_verification_method",
        "domains",
        "verification_method IN ('dns_txt', 'operator')",
    )
    op.create_check_constraint(
        "ck_domains_consecutive_misses",
        "domains",
        "consecutive_misses >= 0",
    )

    # 6. Replace index on next_scan_at and add re-verification indexes
    op.drop_index("ix_domains_schedule_due", table_name="domains")
    op.create_index(
        "ix_domains_schedule_due",
        "domains",
        ["next_scan_at"],
        unique=False,
        postgresql_where=sa.text(
            "verification_status = 'verified' AND scan_interval_hours IS NOT NULL"
        ),
    )
    op.create_index(
        "ix_domains_reverify_due",
        "domains",
        ["next_reverification_at"],
        unique=False,
        postgresql_where=sa.text(
            "verification_status = 'verified' AND verification_method = 'dns_txt'"
        ),
    )
    op.create_index(
        "ix_domains_operator_expiry_due",
        "domains",
        ["verification_expires_at"],
        unique=False,
        postgresql_where=sa.text(
            "verification_status = 'verified' AND verification_method = 'operator'"
        ),
    )

    # 7. Drop legacy client-asserted authorization columns
    op.drop_column("domains", "authorization_note")
    op.drop_column("domains", "authorized")


def downgrade() -> None:
    # Only a verified/unverified flag survives; tokens, methods, expiry and reasons are lost.
    refuse_lossy_downgrade(
        op.get_bind(),
        "SELECT count(*) FROM domains",
        "domain verification state (tokens, method, expiry, reasons, miss counts)",
    )

    # 1. Re-add legacy columns
    op.add_column(
        "domains",
        sa.Column(
            "authorized",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column(
        "domains",
        sa.Column("authorization_note", sa.Text(), nullable=True),
    )

    # 2. Backfill authorized from verification_status
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE domains SET authorized = (verification_status = 'verified'), "
            "authorization_note = verification_reason"
        )
    )

    # 3. Drop new indexes
    op.drop_index(
        "ix_domains_operator_expiry_due",
        table_name="domains",
        postgresql_where=sa.text(
            "verification_status = 'verified' AND verification_method = 'operator'"
        ),
    )
    op.drop_index(
        "ix_domains_reverify_due",
        table_name="domains",
        postgresql_where=sa.text(
            "verification_status = 'verified' AND verification_method = 'dns_txt'"
        ),
    )
    op.drop_index(
        "ix_domains_schedule_due",
        table_name="domains",
        postgresql_where=sa.text(
            "verification_status = 'verified' AND scan_interval_hours IS NOT NULL"
        ),
    )

    # 4. Re-create legacy schedule index
    op.create_index(
        "ix_domains_schedule_due",
        "domains",
        ["next_scan_at"],
        unique=False,
        postgresql_where=sa.text("authorized = true AND scan_interval_hours IS NOT NULL"),
    )

    # 5. Drop check constraints
    op.drop_constraint("ck_domains_consecutive_misses", "domains", type_="check")
    op.drop_constraint("ck_domains_verification_method", "domains", type_="check")
    op.drop_constraint("ck_domains_verification_status", "domains", type_="check")

    # 6. Revert alert_notifications.scan_run_id to NOT NULL
    conn.execute(sa.text("DELETE FROM alert_notifications WHERE scan_run_id IS NULL"))
    op.alter_column("alert_notifications", "scan_run_id", nullable=False)

    # 7. Drop verification columns
    op.drop_column("domains", "next_reverification_at")
    op.drop_column("domains", "verification_expires_at")
    op.drop_column("domains", "verification_reason")
    op.drop_column("domains", "consecutive_misses")
    op.drop_column("domains", "last_checked_at")
    op.drop_column("domains", "verified_at")
    op.drop_column("domains", "verification_method")
    op.drop_column("domains", "verification_token")
    op.drop_column("domains", "verification_status")
