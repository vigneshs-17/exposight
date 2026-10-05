"""Just-in-time (JIT) user upsert with 5-minute update throttling."""

import uuid

from sqlalchemy import func, or_, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from asm.db.models import User


def upsert_user(session: Session, user_id: uuid.UUID, email: str) -> User:
    """Upsert user record just-in-time on authenticated request.

    Updates last_seen_at only when it is older than 5 minutes, to avoid write
    amplification on rapid consecutive requests. A changed email is written
    immediately, because invite acceptance compares it to the invite email.
    """
    stmt = insert(User).values(
        id=user_id,
        email=email,
        created_at=func.now(),
        last_seen_at=func.now(),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[User.id],
        set_={
            "email": stmt.excluded.email,
            "last_seen_at": func.now(),
        },
        # Always write a changed email at once (invites compare it); otherwise
        # throttle last_seen_at writes to once per 5 minutes.
        where=or_(
            User.last_seen_at < func.now() - text("INTERVAL '5 minutes'"),
            User.email.is_distinct_from(stmt.excluded.email),
        ),
    )
    session.execute(stmt)
    user = session.get(User, user_id)
    if user is None:
        raise RuntimeError(f"User {user_id} not found after JIT upsert")
    session.refresh(user)
    return user

