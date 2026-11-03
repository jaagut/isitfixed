FROM python:3.13-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY index.html style.css ./
COPY src src
COPY assets assets
ENV CACHE_DB=/data/cache.sqlite3
VOLUME /data
EXPOSE 8080
# The in-process scheduler and SQLite cache use one application worker.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
