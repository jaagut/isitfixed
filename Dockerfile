# syntax=docker/dockerfile:1

# Frontend: minified, content-hashed bundles in /build/dist (scripts/build.mjs).
FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS frontend
WORKDIR /build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@12.16.1 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY scripts scripts
COPY index.html style.css ./
COPY src src
COPY assets assets
RUN pnpm run build

# Runtime: FastAPI backend serving the built frontend.
FROM python:3.13.18-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
LABEL org.opencontainers.image.title="CVE Desk" \
      org.opencontainers.image.description="A compact CVE case workspace with a FastAPI vendor-data cache" \
      org.opencontainers.image.source="https://github.com/jaagut/cve-viewer" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
# Nothing is written outside /data and /tmp at runtime, so the root filesystem can be mounted read-only.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
# Install the locked runtime dependencies into /opt/venv with a pinned uv; uv itself is not kept in the image.
COPY pyproject.toml uv.lock ./
RUN --mount=from=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85,source=/uv,target=/usr/local/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev && rm -rf /tmp/uv-*
COPY backend backend
COPY legal legal
COPY --from=frontend /build/dist dist
RUN python -m compileall -q backend \
    && groupadd --gid 10001 cve-desk \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cve-desk \
    && mkdir -p /data && chown 10001:10001 /data
ENV PATH=/opt/venv/bin:$PATH HOME=/tmp \
    HOST=0.0.0.0 PORT=8080 ADMIN_PORT=8081 \
    CACHE_DB=/data/cache.sqlite3 LOG_DIR=/data/logs FRONTEND_DIR=/app/dist
USER 10001:10001
VOLUME /data
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=5)"]
# One process: the public app (8080) and the admin dashboard (8081) share the event loop, scheduler and SQLite cache.
CMD ["python", "-m", "backend"]
