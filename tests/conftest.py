"""Shared pytest fixtures for ASM SaaS test suite."""

from __future__ import annotations

import json
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import Base, Membership, Organization, User
from asm.db.session import get_db


@pytest.fixture
def crtsh_sample_data() -> list[dict[str, Any]]:
    """Load the realistic crt.sh JSON fixture."""
    fixture_path = Path(__file__).parent / "fixtures" / "crtsh_sample.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def mock_sleep():
    """Autouse fixture to mock time.sleep across tests so no test actually waits."""
    with patch("time.sleep", return_value=None) as mocked:
        yield mocked


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Give every test fresh in-memory rate-limit counters (they are process-global)."""
    from asm.ratelimit import limiter

    limiter.reset()
    yield
    limiter.reset()


def validate_test_database_url(test_db_url: str) -> None:
    """Ensure TEST_DATABASE_URL strictly points to a database name ending with '_test'."""
    parsed = urlsplit(test_db_url)
    db_name = parsed.path.lstrip("/").split("?")[0]
    if not db_name.endswith("_test"):
        pytest.fail(
            f"Safety check failed: database name '{db_name}' in TEST_DATABASE_URL "
            f"must end with '_test' to prevent running tests against non-test databases."
        )


@pytest.fixture(scope="session")
def db_engine():
    """Verify TEST_DATABASE_URL and yield an Engine for the test database."""
    test_db_url = os.getenv("TEST_DATABASE_URL")
    if not test_db_url:
        pytest.skip("TEST_DATABASE_URL not set; skipping database integration tests")

    # Safety check: database name in TEST_DATABASE_URL MUST end with '_test'
    validate_test_database_url(test_db_url)

    engine = create_engine(
        test_db_url, pool_pre_ping=True, connect_args={"connect_timeout": 5}
    )

    # Verify database connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as err:
        pytest.fail(f"Could not connect to PostgreSQL at TEST_DATABASE_URL: {err}")

    # Ensure tables exist for test suite
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine) -> Generator[Session, None, None]:
    """Provide an isolated database session that is rolled back after each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient with get_db and get_current_user overridden."""
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    test_user = db_session.get(User, test_user_id)
    if not test_user:
        test_user = User(id=test_user_id, email="testuser@example.com")
        db_session.add(test_user)
        db_session.flush()

    def _override_get_db():
        yield db_session

    def _override_get_current_user():
        return test_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def clean_db(db_engine) -> Generator[None, None, None]:
    """Ensure database tables are truncated before and after multi-threaded concurrency tests."""
    def _truncate(conn):
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only;"))
        conn.execute(
            text(
                "TRUNCATE TABLE memberships, organizations, users, alert_notifications, "
                "scan_changes, scan_results, scan_stages, scan_runs, domains, audit_events "
                "RESTART IDENTITY CASCADE;"
            )
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_append_only;"))

    with db_engine.begin() as conn:
        _truncate(conn)
    yield
    with db_engine.begin() as conn:
        _truncate(conn)


@pytest.fixture
def lifecycle_client(clean_db, db_engine) -> Generator[TestClient, None, None]:
    """Provide a TestClient connected to db_engine with clean_db truncation for worker tests."""
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")

    def _override_get_db():
        with Session(db_engine) as session:
            yield session

    def _override_get_current_user():
        with Session(db_engine) as session:
            user = session.get(User, test_user_id)
            if not user:
                try:
                    user = User(id=test_user_id, email="testuser@example.com")
                    session.add(user)
                    session.commit()
                except Exception:
                    session.rollback()
                    user = session.get(User, test_user_id)
            return user


    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_org(db_session: Session) -> Organization:
    """Provide a real test organization with real owner membership for test_user."""
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    test_user = db_session.get(User, test_user_id)
    if not test_user:
        test_user = User(id=test_user_id, email="testuser@example.com")
        db_session.add(test_user)
        db_session.flush()

    org = Organization(name="Default Test Org")
    db_session.add(org)
    db_session.flush()

    membership = Membership(org_id=org.id, user_id=test_user.id, role="owner")
    db_session.add(membership)
    db_session.flush()
    return org


@pytest.fixture
def lifecycle_org(clean_db, db_engine) -> Organization:
    """Provide a real organization for worker/lifecycle tests where test_user is owner."""
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    with Session(db_engine) as session:
        user = session.get(User, test_user_id)
        if not user:
            user = User(id=test_user_id, email="testuser@example.com")
            session.add(user)
            session.commit()

        org = Organization(name="Lifecycle Test Org")
        session.add(org)
        session.flush()

        membership = Membership(org_id=org.id, user_id=user.id, role="owner")
        session.add(membership)
        session.commit()
        session.refresh(org)
        return org




