"""`current_user` dependency: protects a route with one parameter, `user: CurrentUser`."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.sessions import get_user_by_token

SESSION_COOKIE = "session"

# One answer for every failure (no cookie, garbage, logged out, expired): attackers learn nothing.
NOT_AUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
)


def current_user(
    db: Annotated[Session, Depends(get_db)],
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> User:
    """Resolve the session cookie to a user, or stop the request with 401."""
    if token is None:
        raise NOT_AUTHENTICATED
    user = get_user_by_token(db, token, now=datetime.now(UTC))
    if user is None:
        raise NOT_AUTHENTICATED
    return user


# Any route that declares `user: CurrentUser` runs the check above before its own code.
CurrentUser = Annotated[User, Depends(current_user)]
