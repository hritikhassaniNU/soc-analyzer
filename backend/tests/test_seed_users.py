import pytest
from sqlalchemy import func, select

from app.models import User
from app.security import verify_password
from app.seed_users import parse_seed_users, seed

# ---- parsing (unit, no database) ----


def test_parses_multiple_entries_and_lowercases_usernames():
    assert parse_seed_users(" Alice:password1 , bob:password2 ") == [
        ("alice", "password1"),
        ("bob", "password2"),
    ]


def test_empty_string_means_no_users():
    assert parse_seed_users("") == []


@pytest.mark.parametrize(
    "raw",
    [
        "alice",                # missing ':password'
        "alice:short",          # password under 8 chars
        "al ice:password1",     # space not allowed in username
        "alice:" + "a" * 73,    # over bcrypt's 72-byte limit
    ],
)
def test_rejects_invalid_entries(raw):
    with pytest.raises(ValueError):
        parse_seed_users(raw)


# ---- seeding (integration, on soc_test) ----


@pytest.mark.integration
def test_first_run_creates_user_with_hashed_password(db_session):
    result = seed(db_session, [("alice", "password1")])

    user = db_session.scalar(select(User).where(User.username == "alice"))
    assert result.created == 1
    assert user.password_hash != "password1"
    assert verify_password("password1", user.password_hash)


@pytest.mark.integration
def test_second_run_is_idempotent(db_session):
    seed(db_session, [("alice", "password1")])
    hash_before = db_session.scalar(select(User.password_hash))

    result = seed(db_session, [("alice", "password1")])

    assert (result.created, result.updated, result.unchanged) == (0, 0, 1)
    assert db_session.scalar(select(func.count()).select_from(User)) == 1
    assert db_session.scalar(select(User.password_hash)) == hash_before  # not re-hashed


@pytest.mark.integration
def test_changed_password_is_updated(db_session):
    seed(db_session, [("alice", "password1")])

    result = seed(db_session, [("alice", "new-password2")])

    user = db_session.scalar(select(User).where(User.username == "alice"))
    assert result.updated == 1
    assert verify_password("new-password2", user.password_hash)
    assert not verify_password("password1", user.password_hash)
