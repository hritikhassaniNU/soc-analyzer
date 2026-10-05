from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select

from app.models import User, UserSession
from app.sessions import (
    create_session,
    delete_expired_sessions,
    delete_session,
    get_user_by_token,
)

pytestmark = pytest.mark.integration

T0 = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)  # fixed clock: tests never sleep


@pytest.fixture
def alice(db_session):
    user = User(username="alice", password_hash="not-used-here")
    db_session.add(user)
    db_session.commit()
    return user


def test_db_stores_hash_not_raw_token(db_session, alice):
    token = create_session(db_session, alice, now=T0)

    stored = db_session.scalar(select(UserSession.token_hash))
    assert stored != token
    assert len(stored) == 64  # hex SHA-256


def test_valid_token_returns_user(db_session, alice):
    token = create_session(db_session, alice, now=T0)

    assert get_user_by_token(db_session, token, now=T0 + timedelta(hours=1)).id == alice.id


def test_unknown_token_returns_none(db_session, alice):
    create_session(db_session, alice, now=T0)

    assert get_user_by_token(db_session, "not-a-real-token", now=T0) is None


def test_expired_token_returns_none(db_session, alice):
    token = create_session(db_session, alice, now=T0)

    just_before = T0 + timedelta(hours=8) - timedelta(seconds=1)
    just_after = T0 + timedelta(hours=8, seconds=1)
    assert get_user_by_token(db_session, token, now=just_before) is not None
    assert get_user_by_token(db_session, token, now=just_after) is None


def test_deleted_session_stops_working(db_session, alice):
    token = create_session(db_session, alice, now=T0)

    delete_session(db_session, token)

    assert get_user_by_token(db_session, token, now=T0) is None


def test_cleanup_removes_only_expired_sessions(db_session, alice):
    create_session(db_session, alice, now=T0)                           # expires T0+8h
    fresh = create_session(db_session, alice, now=T0 + timedelta(hours=6))  # expires T0+14h

    removed = delete_expired_sessions(db_session, now=T0 + timedelta(hours=9))

    assert removed == 1
    assert get_user_by_token(db_session, fresh, now=T0 + timedelta(hours=9)) is not None


def test_deleting_user_cascades_to_sessions(db_session, alice):
    create_session(db_session, alice, now=T0)

    db_session.execute(delete(User).where(User.id == alice.id))
    db_session.commit()

    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
