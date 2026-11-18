import asyncio
import copy
import json
import logging
import re
import time
from contextlib import asynccontextmanager, suppress

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi import Path as APIPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .backoff import Breaker
from .cache import RETENTION, RETENTION_DAYS, Cache
from .errors import NotPublished, Paused, describe
from .ksp import KernelSupport
from .legal import LegalPages
from .providers import DEADLINES, FAMILIES, HOUR, Providers
from .ratelimit import RateLimiter, RateLimitMiddleware, client_address
from .security import BodyLimit, SecurityHeaders, SelectiveGZip
from .settings import Settings
from .stats import Stats
from .tmds import Inventory

logger = logging.getLogger("cve-desk")
MAX_BODY = 256 * 1024
# Background-job sources back off after their first failure (they retry sooner than hourly instead).
JOB_SOURCES = ("tmds-agents", "tmds-ksp")


class Service:
    def __init__(self, cache, providers, clock=time.time, settings=None, breaker=None, stats=None):
        self.cache, self.providers, self.clock = cache, providers, clock
        self.settings = settings or Settings()
        self.breaker = breaker or Breaker(clock)
        self.stats = stats or Stats(cache, clock)
        self.locks = {}
        self.capacity = asyncio.Semaphore(4)
        self.beat = None

    def prune(self):
        self.cache.prune(self.clock())
        active = set(self.cache.ids()) | set(self.cache.watched_ids())
        self.locks = {key: lock for key, lock in self.locks.items() if key in active or lock.locked()}
        self.providers.prune(clear=not active)

    def make_room(self, cve):
        """Evict the least recently refreshed unwatched entry when the cache is full."""
        ids = self.cache.ids()
        if len(ids) < self.settings.max_cached_cves:
            return
        watched = set(self.cache.watched_ids())
        for candidate in ids:
            lock = self.locks.get(candidate)
            if candidate != cve and candidate not in watched and not (lock and lock.locked()):
                self.cache.delete(candidate)
                return
        raise HTTPException(429, "Cache capacity reached. Try again later.", headers={"Retry-After": "60"})

    def would_fetch(self, cve, families, force=False):
        """Whether a lookup would contact upstream sources (used for the uncached-lookup rate limit)."""
        row = self.cache.peek(cve)
        now = self.clock()
        if not row or (row["unwatched_since"] is not None and row["unwatched_since"] + RETENTION <= now):
            return True
        if families - row["families"] or not row["attempted"] or now - row["attempted"] >= HOUR:
            return True
        return force and now - row["attempted"] >= 60

    async def get(self, cve, families, force=False, touch=True, publish=None):
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
            created = not row
            if created:
                if not touch and not self.cache.watched(cve):
                    return None
                self.make_room(cve)
                row = dict(
                    payload={"id": cve, "vendorData": {"id": cve, "evidence": {}, "sources": {}}},
                    families=set(),
                    unwatched_since=None if self.cache.watched(cve) else now,
                    attempted=0,
                )
            missing = families - row["families"]
            due = not row["attempted"] or now - row["attempted"] >= HOUR
            manual = force and now - row["attempted"] >= 60
            row["families"] |= families
            # Refresh updates cannot change the watch/retention lifecycle.
            self.cache.put(cve, row)
            if due or manual or missing:
                kind = "scheduled" if not touch else "manual" if manual and not due else "on_demand"
                self.stats.incr(f"refresh.{kind}")
                async with self.capacity:
                    if due or manual:
                        await self.refresh(cve, row, row["families"], full=True, publish=publish)
                    else:
                        # Only newly selected vendors are fetched; the hourly clock is unchanged.
                        await self.refresh(cve, row, missing, full=False, publish=publish)
            result = copy.deepcopy(row["payload"])
            empty = not result.get("record") and not any(result["vendorData"]["evidence"].values())
            if empty and created and not self.cache.watched(cve):
                # Failed lookups are not stored, so unknown IDs cannot fill the cache.
                self.cache.delete(cve)
            current = self.cache.get(cve)
            lifecycle = current["unwatched_since"] if current else now
            result["cache"] = {
                "watched": lifecycle is None,
                "expiresAt": int((lifecycle + RETENTION) * 1000) if lifecycle is not None else None,
                "lastAttempt": int(row["attempted"] * 1000),
                "retentionDays": RETENTION_DAYS,
                "refreshAfter": int((row["attempted"] + 60) * 1000),
            }
            if empty:
                raise HTTPException(
                    404 if result.get("notFound") else 502,
                    result.get("error", "No CVE or vendor data could be retrieved. Try again later."),
                )
            return result

    async def fetch(self, name, work):
        """Run one source fetch under its deadline and circuit breaker; return the result or the exception."""
        try:
            self.breaker.check(name)
        except Paused as paused:
            return paused
        self.stats.incr(f"fetch.{name}")
        try:
            result = await asyncio.wait_for(work(), DEADLINES[name])
        except Exception as error:
            result = error
            if not isinstance(error, NotPublished):
                self.stats.incr(f"failure.{name}")
        self.breaker.record(name, result)
        return result

    def failure(self, prefix, name, error):
        failure = {"error": f"{prefix}: {describe(error)}"}
        if retry := self.breaker.retry_after(name):
            failure["retryAfter"] = int(retry * 1000)
        return failure

    async def refresh(self, cve, row, families, full=True, publish=None):
        families = sorted(families)
        payload = row["payload"]
        fetch_record = full or not payload.get("record")

        async def area(name, work):
            return name, await self.fetch(name, work)

        jobs = [asyncio.create_task(area("record", lambda: self.providers.record(cve)))] if fetch_record else []
        jobs += [
            asyncio.create_task(area(family, lambda family=family: self.providers.vendor(family, cve)))
            for family in families
        ]
        try:
            for job in asyncio.as_completed(jobs):
                name, result = await job
                now = self.clock()
                if name == "record":
                    payload.pop("retryAfter", None)
                    if isinstance(result, Exception):
                        payload.update(self.failure("CVE source unavailable", name, result))
                        if isinstance(result, NotPublished):
                            payload["notFound"] = True
                    else:
                        payload["record"], payload["checked"] = result, int(now * 1000)
                        payload.pop("error", None)
                        payload.pop("notFound", None)
                else:
                    vendors = payload["vendorData"]
                    if isinstance(result, NotPublished):
                        previous = {
                            k: v
                            for k, v in vendors["sources"].get(name, {}).items()
                            if k not in ("error", "attempted", "checked", "retryAfter")
                        }
                        vendors["sources"][name] = {
                            **previous,
                            "notPublished": describe(result),
                            "checked": int(now * 1000),
                            "mode": "API cache",
                        }
                    elif isinstance(result, Exception):
                        previous = {k: v for k, v in vendors["sources"].get(name, {}).items() if k != "retryAfter"}
                        vendors["sources"][name] = {
                            **previous,
                            **self.failure("Vendor source unavailable", name, result),
                            "attempted": int(now * 1000),
                        }
                    else:
                        evidence, source = result
                        vendors["evidence"].update(evidence)
                        vendors["sources"][name] = source
                self.cache.put(cve, row)
                if publish:
                    publish(copy.deepcopy(payload))
        finally:
            for job in jobs:
                if not job.done():
                    job.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)
        now = self.clock()
        if full:
            row["attempted"] = now
        self.cache.put(cve, row)

    async def tick(self):
        now = self.clock()
        self.prune()
        if dropped := self.cache.prune_workspaces(now - self.settings.workspace_ttl_days * 86400, now):
            logger.info("Removed %d inactive workspace(s)", dropped)
        for cve in self.cache.watched_ids():
            self.beat = time.monotonic()
            row = self.cache.peek(cve)
            if not row or self.clock() - row["attempted"] >= HOUR:
                try:
                    await self.get(cve, self.cache.watch_families(cve), touch=False)
                except HTTPException:
                    pass  # Source failures are retained for the next scheduled retry.
        self.stats.flush()

    async def worker(self):
        while True:
            self.beat = time.monotonic()
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
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
    # The configurable per-workspace limit is checked in the endpoint; this bounds request parsing.
    cases: list[Watch] = Field(max_length=2000)


CASE_PATH = re.compile(r"cve[-_]\d{4}[-_]\d{4,}", re.IGNORECASE)
# Worker heartbeat age (seconds) after which /api/health reports "degraded".
STALE_AFTER = {"refresh": 600, "tmds-agents": 1800, "tmds-ksp": 1800}


class Static(StaticFiles):
    """Static files with a fixed Cache-Control header."""

    def __init__(self, *args, cache_control, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache_control = cache_control

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = self.cache_control
        return response


def frontend_manifest(directory):
    """Hashed asset names written by scripts/build.mjs, e.g. {"/style.css": "/static/style-1a2b3c4d.css"}."""
    try:
        return json.loads((directory / "manifest.json").read_text())
    except (OSError, ValueError):
        return {}


def create_app(db_path=None, *, providers=None, clock=time.time, background=True, serve_frontend=True, settings=None):
    settings = settings or Settings.from_env()
    frontend = settings.frontend_dir
    legal = LegalPages(settings, stylesheet=frontend_manifest(frontend).get("/style.css", "/style.css"))
    limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(app):
        legal.warn_if_unconfigured()
        cache = app.state.cache = Cache(db_path or settings.cache_db, clock)
        breaker = app.state.breaker = Breaker(clock, thresholds={name: 1 for name in JOB_SOURCES})
        stats = app.state.stats = Stats(cache, clock)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60, connect=10),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20),
            headers={"User-Agent": settings.user_agent},
        ) as client:
            source = providers or Providers(client, clock)
            service = app.state.service = Service(cache, source, clock, settings, breaker, stats)
            service.prune()
            jobs = dict(cache=cache, client=client, clock=clock, breaker=breaker, stats=stats)
            inventory = app.state.inventory = Inventory(**jobs)
            ksp = app.state.ksp = KernelSupport(**jobs)
            workers = app.state.workers = {}
            if background:
                workers["refresh"] = (service, asyncio.create_task(service.worker()))
                if providers is None and settings.tmds_enabled:
                    workers["tmds-agents"] = (inventory, asyncio.create_task(inventory.worker()))
                    workers["tmds-ksp"] = (ksp, asyncio.create_task(ksp.worker()))
            try:
                yield
            finally:
                for _, task in workers.values():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                pending = list(getattr(source, "pending", {}).values())
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                with suppress(Exception):
                    stats.flush()
                cache.close()

    docs = settings.api_docs
    app = FastAPI(
        title="CVE Desk",
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings, app.state.limiter, app.state.legal = settings, limiter, legal
    app.state.started = time.time()

    def rejected(budget):
        if stats := getattr(app.state, "stats", None):
            stats.incr(f"ratelimited.{budget}")

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "PUT"],
            allow_headers=["Content-Type"],
        )
    app.add_middleware(
        RateLimitMiddleware, limiter=limiter, per_minute=settings.rate_limit_requests, on_reject=rejected
    )
    app.add_middleware(BodyLimit, limit=MAX_BODY)
    app.add_middleware(SelectiveGZip)
    app.add_middleware(SecurityHeaders, connect_src=settings.csp_connect_src, hsts=settings.hsts, docs=docs)

    def limit(request, budget, per_minute, detail, global_per_minute=0):
        client = limiter.client_key(client_address(request.scope))
        wait = limiter.hit(budget, client, per_minute)
        if not wait and (wait := limiter.hit(f"{budget}-global", b"", global_per_minute)):
            limiter.refund(budget, client, per_minute)
            budget = f"{budget}-global"
        if wait:
            rejected(budget)
            raise HTTPException(429, detail.format(wait=wait), headers={"Retry-After": str(wait)})

    def lookup(request, cve, families, refresh):
        if not families <= FAMILIES:
            raise HTTPException(422, "Unknown vendor family")
        if refresh and not settings.manual_refresh:
            raise HTTPException(403, "Manual refresh is disabled on this server.")
        if app.state.service.would_fetch(cve, families, refresh):
            limit(
                request,
                "lookups",
                settings.rate_limit_lookups,
                "Too many new lookups. Try again in {wait} seconds.",
                settings.rate_limit_lookups_global,
            )

    @app.get("/api/config")
    async def config(response: Response):
        response.headers["Cache-Control"] = "no-store"
        return {
            "version": settings.version,
            "manualRefresh": settings.manual_refresh,
            "tmds": settings.tmds_enabled,
            "legal": legal.enabled(),
            "sourceUrl": settings.source_url or None,
            "retentionDays": RETENTION_DAYS,
        }

    @app.get("/api/tmds")
    async def tmds(response: Response):
        response.headers["Cache-Control"] = "no-store"
        if not settings.tmds_enabled:
            return {"enabled": False}
        return {"enabled": True, **app.state.inventory.snapshot(), "ksp": app.state.ksp.snapshot()}

    @app.get("/api/health")
    async def health(response: Response):
        response.headers["Cache-Control"] = "no-store"
        now = time.monotonic()
        workers, degraded = {}, False
        for name, (owner, task) in getattr(app.state, "workers", {}).items():
            age = None if owner.beat is None else round(now - owner.beat, 1)
            workers[name] = age
            degraded |= task.done() or (age is not None and age > STALE_AFTER[name])
        return {
            "status": "degraded" if degraded else "ok",
            "version": settings.version,
            "workers": workers,
            "retentionDays": RETENTION_DAYS,
        }

    @app.put("/api/workspaces/{workspace}/watches")
    async def watches(request: Request, body: Watchlist, workspace: str = APIPath(pattern=r"^[a-f0-9-]{36}$")):
        limit(request, "watches", settings.rate_limit_watches, "Too many watch updates. Try again in {wait} seconds.")
        entries = {entry.id: entry.model_dump() for entry in body.cases}
        if len(entries) > settings.max_watches_per_workspace:
            raise HTTPException(
                422,
                f"A workspace can watch at most {settings.max_watches_per_workspace} cases. Archive or delete some.",
            )
        service = app.state.service
        service.prune()
        if len(set(service.cache.watched_ids()) | set(entries)) > settings.max_watched_cves:
            raise HTTPException(429, "Watch capacity reached", headers={"Retry-After": "3600"})
        service.cache.sync_watches(workspace, list(entries.values()), service.clock())
        return {"watched": len(entries), "unwatchedRetentionDays": RETENTION_DAYS}

    @app.get("/api/cves/{cve}")
    async def case(
        request: Request,
        response: Response,
        cve: str = APIPath(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32),
        families: str = Query("rhel,sles,debian,ubuntu,alpine", max_length=80),
        refresh: bool = False,
    ):
        selected = set(filter(None, families.split(",")))
        lookup(request, cve, selected, refresh)
        result = await app.state.service.get(cve, selected, refresh)
        response.headers["Cache-Control"] = "no-store"
        return result

    @app.get("/api/cves/{cve}/stream")
    async def stream(
        request: Request,
        cve: str = APIPath(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32),
        families: str = Query("", max_length=80),
        refresh: bool = False,
    ):
        selected = set(filter(None, families.split(",")))
        lookup(request, cve, selected, refresh)

        async def events():
            queue = asyncio.Queue()

            async def run():
                try:
                    result = await app.state.service.get(cve, selected, refresh, publish=queue.put_nowait)
                    queue.put_nowait(result)
                except HTTPException as error:
                    queue.put_nowait({"error": str(error.detail), "failed": True})
                except Exception:
                    logger.exception("Progressive lookup failed")
                    queue.put_nowait({"error": "Source lookup failed. Try again later.", "failed": True})
                finally:
                    queue.put_nowait(None)

            task = asyncio.create_task(run())
            try:
                while True:
                    item = await queue.get()
                    if item is None:
                        break
                    yield json.dumps(item) + "\n"
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        return StreamingResponse(
            events(),
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    def legal_page(page):
        async def handler():
            document = legal.page(page)
            if document is None:
                raise HTTPException(404, "Not found")
            return HTMLResponse(document, headers={"Cache-Control": "no-cache"})

        return handler

    def redirect(target):
        async def handler():
            return RedirectResponse(target, status_code=301)

        return handler

    for page, alias in (("imprint", "impressum"), ("privacy", "datenschutz")):
        app.get(f"/{page}", include_in_schema=False)(legal_page(page))
        app.get(f"/{alias}", include_in_schema=False)(redirect(f"/{page}"))

    if serve_frontend and settings.serve_frontend:
        # Explicit routes and mounts keep the database, backend files and repository private.
        index = frontend / "index.html"
        page_headers = {"Cache-Control": "no-cache"}

        @app.get("/", include_in_schema=False)
        @app.get("/index.html", include_in_schema=False)
        async def home():
            return FileResponse(index, headers=page_headers)

        if (frontend / "style.css").is_file():  # unbuilt sources (development)

            @app.get("/style.css", include_in_schema=False)
            async def style():
                return FileResponse(frontend / "style.css", headers=page_headers)

        # Case links such as /CVE-2024-3094 load the app, which opens that case.
        @app.get("/{case_path}", include_in_schema=False)
        async def case_page(case_path: str):
            if not CASE_PATH.fullmatch(case_path):
                raise HTTPException(404, "Not found")
            return FileResponse(index, headers=page_headers)

        for prefix, cache_control in (
            ("static", "public, max-age=31536000, immutable"),  # content-hashed bundle files
            ("src", "no-cache"),  # unbuilt sources (development)
            ("assets", "public, max-age=86400"),
        ):
            if (frontend / prefix).is_dir():
                app.mount(f"/{prefix}", Static(directory=frontend / prefix, cache_control=cache_control), name=prefix)
    return app


def __getattr__(name):
    # `uvicorn backend.main:app` (development) builds the app on first access instead of at import time.
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
