"""ORM models (tables). Every model subclasses app.db.Base; Alembic imports this module."""

from datetime import datetime

from sqlalchemy import DateTime, Identity, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    """A SOC analyst who can log in. Seeded from env, no sign-up."""

    __tablename__ = "users"

    # IDENTITY (SQL-standard auto-numbering), not legacy SERIAL.
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    # Stored lowercase so login is case-insensitive; unique in the DB (not just in app code).
    username: Mapped[str] = mapped_column(String(64), unique=True)
    # bcrypt hash only, never the plain password.
    password_hash: Mapped[str] = mapped_column(String(255))
    # timestamptz, filled by Postgres: an absolute moment in time (we work in UTC).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
