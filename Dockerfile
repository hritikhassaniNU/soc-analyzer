FROM python:3.12-slim

# uv binary, copied from the official image (no pip install needed)
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

WORKDIR /app

# 1) Dependencies first: this layer stays cached until pyproject.toml / uv.lock change.
#    --frozen: use uv.lock exactly (fail if outdated). --no-dev: skip test tools.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# 2) Our code last, since it changes most often. Alembic files too, for the migrate service.
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app

# Never run as root inside the container.
RUN useradd --create-home appuser
USER appuser

ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
# 0.0.0.0 so the published port can reach the server from outside the container.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
