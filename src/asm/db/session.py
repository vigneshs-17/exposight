"""Database engine and session management for Exposight."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from asm.config import get_settings


@lru_cache
def get_engine(database_url: str | None = None) -> Engine:
    """Create and cache the SQLAlchemy database engine."""
    url = database_url or get_settings().database_url
    return create_engine(
        url,
        pool_pre_ping=True,
        echo=False,
    )


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Return a sessionmaker bound to the engine."""
    eng = engine or get_engine()
    return sessionmaker(bind=eng, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a transactional database session."""
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


__all__ = ["get_engine", "get_session_factory", "get_db"]


