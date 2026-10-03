import pytest

from app.security import hash_password, verify_password


def test_correct_password_verifies():
    hashed = hash_password("s3cret-pass")

    assert verify_password("s3cret-pass", hashed) is True


def test_wrong_password_fails():
    hashed = hash_password("s3cret-pass")

    assert verify_password("wrong-pass", hashed) is False


def test_same_password_gets_different_hashes():
    # Different random salt each time, so equal passwords don't produce equal hashes.
    assert hash_password("same") != hash_password("same")


def test_hash_does_not_contain_plain_password():
    hashed = hash_password("s3cret-pass")

    assert "s3cret-pass" not in hashed
    assert hashed.startswith("$2b$12$")


def test_password_over_72_bytes_is_rejected_when_hashing():
    with pytest.raises(ValueError):
        hash_password("a" * 73)


def test_password_over_72_bytes_never_verifies():
    hashed = hash_password("a" * 72)

    assert verify_password("a" * 73, hashed) is False
