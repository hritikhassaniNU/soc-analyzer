"""Shared pytest setup: point the app at a separate `soc_test` database.

This module runs before any test module is imported. It must switch DATABASE_URL
to the test database BEFORE anything imports app.db (which creates the engine on import),
otherwise tests would silently use the dev database.
"""

import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.config import get_settings

TEST_DB_NAME = "soc_test"
BACKEND_DIR = Path(__file__).resolve().parent.parent

try:
    _dev_url = make_url(get_settings().database_url)  # from env or ../.env
except ValidationError:
    _dev_url = None  # no DATABASE_URL: unit tests still run, DB tests fail with a clear message

if _dev_url is not None:
    _test_url = _dev_url.set(database=TEST_DB_NAME)
    os.environ["DATABASE_URL"] = _test_url.render_as_string(hide_password=False)
    get_settings.cache_clear()  # next get_settings() call sees the test URL


def _create_test_database_if_missing() -> None:
    # CREATE DATABASE can't run inside a transaction, so connect to the built-in
    # `postgres` maintenance DB with autocommit.
    admin = create_engine(_test_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": TEST_DB_NAME}
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{TEST_DB_NAME}"'))
    finally:
        admin.dispose()


@pytest.fixture(scope="session")
def migrated_db():
    """Once per test run: make sure soc_test exists and is at the latest migration."""
    if _dev_url is None:
        pytest.fail("DATABASE_URL is not set (copy .env.example to .env and start the db)")

    from alembic import command
    from alembic.config import Config

    _create_test_database_if_missing()
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")  # the real migrations, so tests also prove they work


@pytest.fixture
def db_session(migrated_db):
    """A DB session on an empty database. Tables are truncated BEFORE each test."""
    import app.models  # noqa: F401  (registers tables on Base.metadata)
    from app.db import Base, SessionLocal, engine

    table_names = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    if table_names:
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {table_names} RESTART IDENTITY CASCADE"))

    with SessionLocal() as session:
        yield session
