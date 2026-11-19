# syntax=docker/dockerfile:1

# Frontend: minified, content-hashed bundles in /build/dist (scripts/build.mjs).
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# The pnpm version lives in package.json devDependencies, where Dependabot updates it.
RUN npm install --global "pnpm@$(node -p "require('./package.json').devDependencies.pnpm")"
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY scripts scripts
COPY index.html style.css ./
COPY src src
COPY assets assets
RUN pnpm run build

# Runtime: FastAPI backend serving the built frontend.
FROM python:3.15.2-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="Is It Fixed" \
      org.opencontainers.image.description="A compact CVE case workspace with a FastAPI vendor-data cache" \
      org.opencontainers.image.source="https://github.com/jaagut/isitfixed" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
# Apply Debian security fixes newer than the pinned base image. pip and its
# vendored libraries are build tooling; runtime dependencies are installed by uv.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall --yes pip
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
    && groupadd --gid 10001 isitfixed \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin isitfixed \
    && mkdir -p /data && chown 10001:10001 /data
ENV PATH=/opt/venv/bin:$PATH HOME=/tmp \
    HOST=0.0.0.0 PORT=8080 \
    CACHE_DB=/data/cache.sqlite3 LOG_DIR=/data/logs FRONTEND_DIR=/app/dist
# The commit the image was built from, reported by /api/health and shown in the footer (CI passes the SHA).
ARG GIT_COMMIT=""
ENV GIT_COMMIT=$GIT_COMMIT
USER 10001:10001
VOLUME /data
# The admin dashboard is off by default; set ADMIN_PORT (for example 8081) and keep that port private.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=5)"]
# One process: the public app (8080) and the optional admin dashboard (ADMIN_PORT) share the event loop, scheduler and SQLite cache.
CMD ["python", "-m", "backend"]
