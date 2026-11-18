FROM python:3.13-slim
WORKDIR /app
# Install the locked runtime dependencies into /opt/venv with a pinned uv; uv itself is not kept in the image.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
RUN --mount=from=ghcr.io/astral-sh/uv:0.13.8,source=/uv,target=/usr/local/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev
ENV PATH=/opt/venv/bin:$PATH
COPY backend backend
COPY index.html style.css ./
COPY src src
COPY assets assets
ENV CACHE_DB=/data/cache.sqlite3
VOLUME /data
EXPOSE 8080
# The in-process scheduler and SQLite cache use one application worker.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
