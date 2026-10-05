"""Login sessions: create, look up, delete, clean up.

The browser cookie holds a random token; the database stores only its SHA-256 hash.
`now` is passed in (not read inside) so tests can control time without sleeping.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import User, UserSession


def _hash_token(token: str) -> str:
    # Fast hash is fine here: a 256-bit random token can't be guessed, unlike a password.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User, now: datetime) -> str:
    """Create a session for `user` and return the RAW token (only for the cookie)."""
    token = secrets.token_urlsafe(32)  # 32 bytes = 256 bits from the OS's secure RNG
    db.add(
        UserSession(
            token_hash=_hash_token(token),
            user_id=user.id,
            expires_at=now + timedelta(hours=get_settings().session_ttl_hours),
        )
    )
    db.commit()
    return token


def get_user_by_token(db: Session, token: str, now: datetime) -> User | None:
    """Return the user for a valid, unexpired session token; otherwise None."""
    return db.scalar(
        select(User)
        .join(UserSession, UserSession.user_id == User.id)
        .where(UserSession.token_hash == _hash_token(token), UserSession.expires_at > now)
    )


def delete_session(db: Session, token: str) -> None:
    """Logout: remove the session so the cookie stops working immediately."""
    db.execute(delete(UserSession).where(UserSession.token_hash == _hash_token(token)))
    db.commit()


def delete_expired_sessions(db: Session, now: datetime) -> int:
    """Housekeeping (expired sessions are already rejected). Returns rows removed."""
    result = db.execute(delete(UserSession).where(UserSession.expires_at <= now))
    db.commit()
    return result.rowcount
