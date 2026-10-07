"""Rebuild the local test database from the Alembic migrations.

Drops and recreates the database named in TEST_DATABASE_URL (the name must end
in "_test"), then runs `alembic upgrade head` and `alembic check`, so the local
schema is the one production gets, not one built from the models.

    python scripts/reset_test_db.py
"""

import os
import subprocess
import sys
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import make_url

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    raw = os.getenv("TEST_DATABASE_URL")
    if not raw:
        sys.stderr.write("TEST_DATABASE_URL is not set.\n")
        return 1
    url = make_url(raw)
    name = url.database or ""
    if not name.endswith("_test"):
        sys.stderr.write(f"Refusing: database name {name!r} does not end with '_test'.\n")
        return 1

    admin = sa.create_engine(
        url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 5},
    )
    with admin.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
    admin.dispose()
    print(f"Recreated database {name}.")

    # Same environment as the migration tests: no app role grants on a local test DB.
    env = {k: v for k, v in os.environ.items() if k not in ("ENVIRONMENT", "APP_DB_USER")}
    env["DATABASE_URL"] = raw
    for args in (("upgrade", "head"), ("check",)):
        result = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=REPO, env=env)
        if result.returncode != 0:
            sys.stderr.write(f"alembic {' '.join(args)} failed.\n")
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
