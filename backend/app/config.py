from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """App configuration, read from environment variables (and `.env` if present)."""

    # Root .env when run from backend/ (../.env); a local .env, if present, wins.
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")

    # Required on purpose: no default, so a missing value fails at startup
    # instead of silently connecting to the wrong database.
    database_url: str

    # Analyst accounts to create/update at startup: "user1:pass1,user2:pass2". Empty = none.
    seed_users: str = ""


@lru_cache
def get_settings() -> Settings:
    """Read settings once and reuse them. A function (not a global) so tests can override it."""
    return Settings()
