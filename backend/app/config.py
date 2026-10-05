from functools import lru_cache
from pathlib import Path
from typing import Literal

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

    # Absolute session lifetime after login (never extended).
    session_ttl_hours: int = 8

    # Send the session cookie only over HTTPS. False locally (http://localhost), True in production.
    cookie_secure: bool = False

    # Where uploaded files live. Default: the gitignored data/ folder at the project root
    # (when running from backend/). In Docker: /data on a shared volume.
    storage_dir: Path = Path("../data")

    # Largest accepted upload. Checked early from Content-Length and again while copying.
    max_upload_mb: int = 1024

    # Zip-bomb guard: a gzip upload may expand to at most this much (the upload limit above only
    # sees the compressed size). Beyond it the analysis fails with a clear message.
    max_uncompressed_mb: int = 10240

    # Resource limits for DuckDB in the worker (it otherwise takes most of the machine).
    # Above the memory limit DuckDB spills to a temp directory instead of failing.
    duckdb_memory_limit: str = "1GB"
    duckdb_threads: int = 2

    # Company storage where large uploads are expected ("host1,host2"; subdomains match too).
    # Large uploads there are down-weighted when ranking incidents, not hidden: a personal account
    # on the same service looks identical by hostname.
    approved_upload_hosts: str = "acme.sharepoint.com,drive.google.com"

    # Claude-written summaries (optional). Without a key the template summary is used.
    # Set ANTHROPIC_API_KEY in .env yourself; never commit it.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    llm_timeout_seconds: float = 30.0  # per-upload summary in the worker (nobody is waiting on it)
    # On-demand analyses (dashboard, user profile): an analyst clicked and waits; company-wide input
    # is bigger and the model thinks first, so 30 s cut it off into the template.
    llm_review_timeout_seconds: float = 90.0

    # Worker log format: "text" (readable) or "json" (one object per line, for Cloud Logging).
    log_format: Literal["text", "json"] = "text"

    # Built React app (frontend/dist). Set in the Docker image; unset in development (Vite serves it).
    static_dir: Path | None = None


@lru_cache
def get_settings() -> Settings:
    """Read settings once and reuse them. A function (not a global) so tests can override it."""
    return Settings()
