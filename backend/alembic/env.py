from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

import app.models
from app.config import get_settings
from app.db import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Single source of configuration: the DB URL comes from our Settings (env / .env),
# never from alembic.ini, so no password lives in file.
config.set_main_option("sqlalchemy.url", get_settings().database_url)

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    # Keep loggers that already exist: by default fileConfig disables them, which silenced the
    # app's warnings for the rest of the process whenever migrations ran in-process (tests).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Our models' metadata, so `alembic revision autogenerate` can diff models vs. the DB.
target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to):
    """Ignore per-upload event partitions (events_u42, ...), created at runtime by the worker.

    Without this, autogenerate sees tables with no matching model and proposes DROP TABLE,
    which would delete real uploaded data.
    """
    if type_ == "table" and name and name.startswith("events_u") and name[8:].isdigit():
        return False
    return True

# other values from the config, defined by the needs of env.py,
# my_important_option = config.get_main_option("my_important_option")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        include_object=include_object,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, include_object=include_object
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
