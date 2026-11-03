import asyncio
import copy
from contextlib import asynccontextmanager, suppress
import logging
import os
from pathlib import Path
import time

from fastapi import FastAPI, HTTPException, Path as APIPath, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel, Field, field_validator

from .cache import Cache, RETENTION
from .providers import FAMILIES, HOUR, Providers

ROOT = Path(__file__).resolve().parent.parent
logger = logging.getLogger("cve-desk")


class Service:
    def __init__(self, cache, providers, clock=time.time):
        self.cache, self.providers, self.clock = cache, providers, clock
        self.locks = {}
        self.capacity = asyncio.Semaphore(4)

    def prune(self):
        self.cache.prune(self.clock())
        active = set(self.cache.ids()) | set(self.cache.watched_ids())
        self.locks = {key: lock for key, lock in self.locks.items() if key in active or lock.locked()}
        self.providers.prune(clear=not active)

    async def get(self, cve, families, force=False, touch=True):
        self.prune()
        lock = self.locks.setdefault(cve, asyncio.Lock())
        async with lock:
            now = self.clock()
            if not touch and not self.cache.watched(cve):
                return None
            row = self.cache.get(cve)
            if row and row["unwatched_since"] is not None and row["unwatched_since"] + RETENTION <= now:
                self.cache.prune(now)
                row = None
            if not row:
                if not touch and not self.cache.watched(cve):
                    return None
                if len(self.cache.ids()) >= 1000:
                    raise HTTPException(429, "Cache capacity reached. Try again later.")
                row = dict(payload={"id": cve, "vendorData": {"id": cve, "evidence": {}, "sources": {}}}, families=set(), unwatched_since=None if self.cache.watched(cve) else now, attempted=0)
            missing = families - row["families"]
            due = not row["attempted"] or now - row["attempted"] >= HOUR
            manual = force and now - row["attempted"] >= 60
            row["families"] |= families
            # Refresh updates cannot change the watch/retention lifecycle.
            self.cache.put(cve, row)
            if due or manual or missing:
                async with self.capacity:
                    await self.refresh(cve, row)
            result = copy.deepcopy(row["payload"])
            lifecycle = self.cache.get(cve)["unwatched_since"]
            result["cache"] = {"watched": lifecycle is None, "expiresAt": int((lifecycle + RETENTION) * 1000) if lifecycle is not None else None, "lastAttempt": int(row["attempted"] * 1000), "retentionDays": 10, "refreshAfter": int((row["attempted"] + 60) * 1000)}
            if not result.get("record") and not any(result["vendorData"]["evidence"].values()):
                raise HTTPException(502, result.get("error", "No CVE or vendor data could be retrieved. Try again later."))
            return result

    async def refresh(self, cve, row):
        families = sorted(row["families"])
        results = await asyncio.gather(self.providers.record(cve), *(self.providers.vendor(family, cve) for family in families), return_exceptions=True)
        payload = row["payload"]
        now = self.clock()
        if isinstance(results[0], Exception):
            payload["error"] = f"CVE source unavailable: {results[0]}"
        else:
            payload["record"], payload["checked"] = results[0], int(now * 1000)
            payload.pop("error", None)
        vendors = payload["vendorData"]
        for family, result in zip(families, results[1:]):
            if isinstance(result, Exception):
                vendors["sources"][family] = {**vendors["sources"].get(family, {}), "error": f"Vendor source unavailable: {result}", "attempted": int(now * 1000)}
            else:
                evidence, source = result
                vendors["evidence"].update(evidence)
                vendors["sources"][family] = source
        row["attempted"] = now
        self.cache.put(cve, row)

    async def tick(self):
        self.prune()
        for cve in self.cache.watched_ids():
            row = self.cache.get(cve)
            if not row or self.clock() - row["attempted"] >= HOUR:
                try:
                    await self.get(cve, self.cache.watch_families(cve), touch=False)
                except HTTPException:
                    pass  # Source failures are retained for the next scheduled retry.

    async def worker(self):
        while True:
            try:
                await self.tick()
            except Exception:
                logger.exception("Background refresh failed")
            await asyncio.sleep(60)


class Watch(BaseModel):
    model_config = {"extra": "forbid"}
    id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    families: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("families")
    @classmethod
    def valid_families(cls, value):
        if not set(value) <= FAMILIES:
            raise ValueError("Unknown vendor family")
        return sorted(set(value))


class Watchlist(BaseModel):
    model_config = {"extra": "forbid"}
    cases: list[Watch] = Field(max_length=1000)


def create_app(db_path=None, *, providers=None, clock=time.time, background=True, serve_frontend=True):
    @asynccontextmanager
    async def lifespan(app):
        cache = Cache(db_path or os.getenv("CACHE_DB", str(ROOT / "data" / "cache.sqlite3")))
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=10), follow_redirects=True, limits=httpx.Limits(max_connections=20), headers={"User-Agent": "CVE-Desk/1.0"}) as client:
            source = providers or Providers(client, clock)
            service = app.state.service = Service(cache, source, clock)
            service.prune()
            worker = asyncio.create_task(service.worker()) if background else None
            try:
                yield
            finally:
                if worker:
                    worker.cancel()
                    with suppress(asyncio.CancelledError):
                        await worker
                pending = list(getattr(source, "pending", {}).values())
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                cache.close()

    app = FastAPI(title="CVE Desk", version="1.0", lifespan=lifespan)
    origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "PUT"], allow_headers=["Content-Type"])

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "retentionDays": 10}

    @app.put("/api/workspaces/{workspace}/watches")
    async def watches(body: Watchlist, workspace: str = APIPath(pattern=r"^[a-f0-9-]{36}$")):
        entries = {entry.id: entry.model_dump() for entry in body.cases}
        service = app.state.service
        service.prune()
        if len(set(service.cache.watched_ids()) | set(entries)) > 1000:
            raise HTTPException(429, "Watch capacity reached")
        service.cache.sync_watches(workspace, list(entries.values()), service.clock())
        return {"watched": len(entries), "unwatchedRetentionDays": 10}

    @app.get("/api/cves/{cve}")
    async def case(response: Response, cve: str = APIPath(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32), families: str = Query("rhel,sles,debian,ubuntu,alpine", max_length=80), refresh: bool = False):
        selected = set(filter(None, families.split(",")))
        if not selected <= FAMILIES:
            raise HTTPException(422, "Unknown vendor family")
        result = await app.state.service.get(cve, selected, refresh)
        response.headers["Cache-Control"] = "no-store"
        return result

    if serve_frontend and os.getenv("SERVE_FRONTEND", "true").lower() == "true":
        # Explicit mounts keep the database, backend files and repository private.
        @app.get("/", include_in_schema=False)
        @app.get("/index.html", include_in_schema=False)
        async def index():
            return FileResponse(ROOT / "index.html", headers={"Cache-Control": "no-cache"})

        @app.get("/style.css", include_in_schema=False)
        async def style():
            return FileResponse(ROOT / "style.css", headers={"Cache-Control": "no-cache"})

        app.mount("/src", StaticFiles(directory=ROOT / "src"), name="src")
        app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")
    return app


app = create_app()
