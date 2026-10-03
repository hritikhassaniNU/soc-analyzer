"""Create/update the analyst accounts listed in SEED_USERS. Safe to run on every start.

Usage:  python -m app.seed_users
"""

import re
import sys
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import User
from app.security import MAX_PASSWORD_BYTES, hash_password, verify_password

USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{1,64}$")
MIN_PASSWORD_LENGTH = 8


@dataclass
class SeedResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0


def parse_seed_users(raw: str) -> list[tuple[str, str]]:
    """Parse 'user1:pass1,user2:pass2' into validated (username, password) pairs."""
    entries = []
    for item in filter(None, (part.strip() for part in raw.split(","))):
        username, sep, password = item.partition(":")
        username = username.strip().lower()
        if not sep:
            raise ValueError(f"Seed entry for '{username}' is missing ':password'")
        if not USERNAME_PATTERN.match(username):
            raise ValueError(f"Invalid username '{username}' (allowed: a-z 0-9 . _ -, max 64)")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password for '{username}' must be at least {MIN_PASSWORD_LENGTH} chars")
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise ValueError(f"Password for '{username}' is longer than {MAX_PASSWORD_BYTES} bytes")
        entries.append((username, password))
    return entries


def seed(session: Session, entries: list[tuple[str, str]]) -> SeedResult:
    """Create missing users, update changed passwords, leave everything else alone."""
    result = SeedResult()
    for username, password in entries:
        user = session.scalar(select(User).where(User.username == username))
        if user is None:
            session.add(User(username=username, password_hash=hash_password(password)))
            result.created += 1
        elif not verify_password(password, user.password_hash):
            user.password_hash = hash_password(password)
            result.updated += 1
        else:
            result.unchanged += 1
    session.commit()
    return result


def main() -> int:
    from app.db import SessionLocal

    try:
        entries = parse_seed_users(get_settings().seed_users)
    except ValueError as exc:
        print(f"seed_users: invalid SEED_USERS: {exc}", file=sys.stderr)
        return 1

    with SessionLocal() as session:
        result = seed(session, entries)
    # Never print passwords.
    print(f"seed_users: {result.created} created, {result.updated} updated, {result.unchanged} unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
