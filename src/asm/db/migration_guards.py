"""Guards that stop Alembic downgrades from silently destroying data (v3.6b B-1)."""

import os

from sqlalchemy import text
from sqlalchemy.engine import Connection

ALLOW_ENV = "ALLOW_DATA_LOSS_DOWNGRADE"


def refuse_lossy_downgrade(conn: Connection, count_sql: str, what_is_lost: str) -> None:
    """Raise unless the downgrade would lose nothing or the operator explicitly allowed it.

    count_sql must return a single number: how many rows would lose data.
    Set ALLOW_DATA_LOSS_DOWNGRADE=1 to proceed anyway (after taking a backup).
    """
    affected = conn.execute(text(count_sql)).scalar() or 0
    if affected and os.getenv(ALLOW_ENV, "").strip() != "1":
        raise RuntimeError(
            f"Refusing downgrade: it would permanently lose {what_is_lost} "
            f"({affected} row(s) affected). Back up the database, then re-run with "
            f"{ALLOW_ENV}=1 if this is intended."
        )
