import pytest
from sqlalchemy import text

from app.db import engine


@pytest.mark.integration
def test_tests_use_the_test_database_not_dev():
    """Guard: if this fails, tests would be writing into the dev database."""
    assert engine.url.database == "soc_test"


@pytest.mark.integration
def test_can_connect_to_postgres(db_session):
    """Needs the Dockerized database: docker compose up -d db"""
    assert db_session.execute(text("SELECT 1")).scalar() == 1


@pytest.mark.integration
def test_migrations_created_users_table(db_session):
    exists = db_session.execute(text("SELECT to_regclass('public.users') IS NOT NULL")).scalar()

    assert exists is True
