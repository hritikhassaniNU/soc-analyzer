# ---- Stage 1: build the React app (Node exists only in this stage) ----
FROM node:22-slim AS frontend
WORKDIR /frontend
# Dependencies first: this layer stays cached until the lockfile changes. `npm ci` = exact lockfile.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Type-check + bundle into dist/ (the generated API types are committed, no backend needed here).
RUN npm run build

# ---- Stage 2: the runtime image (Python API + worker; serves the built UI) ----
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
# Only the built frontend files: no Node.js, no node_modules in the final image.
COPY --from=frontend /frontend/dist ./static

# Never run as root inside the container.
# /data is the uploads volume: created here owned by appuser, because Docker copies this
# ownership into a NEW named volume (otherwise it is root-owned and appuser can't write).
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser

ENV PATH="/app/.venv/bin:$PATH" \
    STATIC_DIR=/app/static
EXPOSE 8000
# 0.0.0.0 so the published port can reach the server from outside the container.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
