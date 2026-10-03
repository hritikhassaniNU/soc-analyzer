"""Password hashing with bcrypt. We store only hashes, never plain passwords."""

import bcrypt

# Work factor: 2^12 rounds (~0.1-0.3 s per hash). Slow on purpose, so guessing is expensive.
BCRYPT_ROUNDS = 12

# bcrypt only uses the first 72 bytes of a password; longer input is rejected, not silently cut.
MAX_PASSWORD_BYTES = 72


def hash_password(plain: str) -> str:
    """Return a salted bcrypt hash like '$2b$12$<22-char salt><31-char hash>'."""
    data = plain.encode("utf-8")
    if len(data) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password longer than {MAX_PASSWORD_BYTES} bytes is not supported by bcrypt")
    return bcrypt.hashpw(data, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    """Check a password against a stored hash (constant-time comparison inside bcrypt)."""
    data = plain.encode("utf-8")
    if len(data) > MAX_PASSWORD_BYTES:
        return False  # could never have been hashed by us; a wrong login, not a server error
    return bcrypt.checkpw(data, hashed.encode("ascii"))
