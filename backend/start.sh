#!/bin/sh
# One-container start for small hosts (e.g. Render's free web service): migrate, seed the analyst
# accounts, run the worker in the background, then the API in the foreground on $PORT.
# Docker Compose doesn't use this: there, migrate, api and worker are separate services.
set -e

alembic upgrade head
python -m app.seed_users
python -m app.worker &
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
