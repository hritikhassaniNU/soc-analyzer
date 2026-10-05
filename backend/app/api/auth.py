"""Authentication routes: Basic credentials once at login, then an httpOnly session cookie."""

import base64
import binascii
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import SESSION_COOKIE, CurrentUser
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security import hash_password, verify_password
from app.sessions import create_session, delete_expired_sessions, delete_session

router = APIRouter(prefix="/api", tags=["auth"])

# Verified against when the username doesn't exist, so unknown and known users take
# the same time to answer (no username enumeration by timing).
_DUMMY_HASH = hash_password("dummy-password-for-timing")

INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
)


class UserOut(BaseModel):
    username: str


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """Parse `Authorization: Basic base64(username:password)`; None if absent or malformed.

    Our own parser instead of FastAPI's HTTPBasic because HTTPBasic (even with
    auto_error=False) answers malformed headers with `WWW-Authenticate: Basic`, which
    pops up the browser's native login dialog, and it only accepts ASCII. RFC 7617
    allows UTF-8, so we decode UTF-8.
    """
    if not header:
        return None
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")  # first ':' only; passwords may contain ':'
    if not sep:
        return None
    return username, password


@router.post("/login")
def login(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    old_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> UserOut:
    # Plain `def`: bcrypt is ~0.3 s of CPU, so FastAPI runs this in a worker thread.
    credentials = parse_basic_auth(authorization)
    if credentials is None:
        raise INVALID_CREDENTIALS  # our 401: same message, no WWW-Authenticate header
    username, password = credentials

    user = db.scalar(select(User).where(User.username == username.lower()))
    if user is None:
        verify_password(password, _DUMMY_HASH)  # same cost as a real check
        raise INVALID_CREDENTIALS
    if not verify_password(password, user.password_hash):
        raise INVALID_CREDENTIALS

    now = datetime.now(UTC)
    if old_token:
        delete_session(db, old_token)  # session fixation defense: never reuse a prior session
    delete_expired_sessions(db, now)   # housekeeping, piggybacking on a rare event
    token = create_session(db, user, now)

    settings = get_settings()
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,       # JavaScript can't read it (XSS can't steal it)
        samesite="lax",      # not sent on cross-site POSTs (CSRF)
        secure=settings.cookie_secure,
        path="/",
    )
    return UserOut(username=user.username)


@router.get("/me")
def me(user: CurrentUser) -> UserOut:
    """Who am I? The React app calls this on load (it can't read the httpOnly cookie itself)."""
    return UserOut(username=user.username)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> None:
    """Idempotent: always 204. Deletes the caller's own session (if any) and clears the cookie.

    POST, not GET: SameSite=Lax still sends cookies on top-level GET navigations,
    so a GET logout could be triggered by any link or <img> on another site.
    """
    if token:
        delete_session(db, token)  # server-side revocation: the token is dead even if copied
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",  # must match the attributes used when setting it
        httponly=True,
        samesite="lax",
        secure=get_settings().cookie_secure,
    )
