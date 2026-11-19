import asyncio
import copy
import json
import logging
import re
import time
from contextlib import asynccontextmanager, nullcontext, suppress

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi import Path as APIPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import logs
from .backoff import Breaker
from .cache import RETENTION, RETENTION_DAYS, Cache, CapacityError
from .errors import NotPublished, Paused, describe
from .ksp import KernelSupport
from .legal import LegalPages
from .providers import DEADLINES, FAMILIES, HOUR, Providers
from .ratelimit import RateLimiter, RateLimitMiddleware, client_address
from .security import BodyLimit, SecurityHeaders, SelectiveGZip
from .settings import Settings
from .stats import Stats
from .tmds import Inventory

logger = logging.getLogger("isitfixed")
MAX_BODY = 256 * 1024
# Background-job sources back off after their first failure (they retry sooner than hourly instead).
JOB_SOURCES = ("tmds-agents", "tmds-ksp")
# A non-stream lookup answers within this many seconds end to end, including waiting for a refresh slot or for
# another request's refresh of the same CVE; on the deadline it returns what it has, with per-source errors.
LOOKUP_DEADLINE = 180
# Scheduled refreshes: watched cases are refreshed oldest first, a few at a time, each under its own deadline.
CASE_DEADLINE = 180
SCHEDULED_CONCURRENCY = 2
PAUSE = 60  # seconds between iterations of the background loops
WORKSPACE_BATCH = 500  # inactive workspaces expired per maintenance iteration
STALL_MARGIN = 120
RECORD = "record"


class Service:
    """Cached CVE lookups and the scheduled refresh of watched cases.

    A case row's ``families`` is the set of sources whose latest result is current: vendor families and ``record``
    (the CVE record). A source joins it only once its success or "not published" answer has been stored; a failed,
    paused, cancelled or timed-out fetch leaves it out, so the next request (or the next scheduled iteration, once
    the source's backoff has passed) fetches it again, independently of the hourly full-refresh clock ``attempted``.
    """

    def __init__(self, cache, providers, clock=time.time, settings=None, breaker=None, stats=None):
        self.cache, self.providers, self.clock = cache, providers, clock
        self.settings = settings or Settings()
        self.breaker = breaker or Breaker(clock)
        self.stats = stats or Stats(cache, clock)
        self.locks = {}
        self.capacity = asyncio.Semaphore(4)
        self.beat = None  # refresh loop progress (monotonic)
        self.maintenance = Heartbeat()

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

    def paused(self, source):
        return self.breaker.retry_after(source) is not None

    def pending(self, families, covered, include_paused=False):
        """Sources (``record`` and ``families``) without a current result; paused ones only if asked."""
        missing = ({RECORD} | families) - covered
        return missing if include_paused else {source for source in missing if not self.paused(source)}

    def due(self, families, covered, attempted, now):
        """Whether a case needs upstream contact: never fetched, hourly refresh due, or a source to (re)try."""
        if covered is None or not attempted or now - attempted >= HOUR:
            return True
        return bool(self.pending(families, covered))

    def would_fetch(self, cve, families, force=False):
        """Whether a lookup would contact upstream sources (used for the uncached-lookup rate limit)."""
        row = self.cache.peek(cve)
        now = self.clock()
        if not row or (row["unwatched_since"] is not None and row["unwatched_since"] + RETENTION <= now):
            return True
        if self.due(families, row["families"], row["attempted"], now):
            return True
        return force and now - row["attempted"] >= 60

    async def get(self, cve, families, force=False, touch=True, publish=None, deadline=None):
        """The case payload; with ``deadline`` (seconds) it returns what is cached when the deadline passes."""
        # Track this lookup's outstanding work independently of historical successful coverage.
        # Initialize before acquiring the case lock, since the end-to-end deadline includes queueing.
        row = self.cache.peek(cve)
        now = self.clock()
        full = not row or not row["attempted"] or now - row["attempted"] >= HOUR
        manual = row and force and now - row["attempted"] >= 60
        pending = (
            (row["families"] if row else set()) | families | {RECORD}
            if full or manual
            else self.pending(families, row["families"], include_paused=True)
        )
        scope = asyncio.timeout(deadline)
        try:
            async with scope:
                return await self._get(cve, families, force, touch, publish, pending)
        except TimeoutError:
            if not scope.expired():
                raise
        return self.partial(cve, pending, touch)

    async def _get(self, cve, families, force, touch, publish, pending):
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
                self.make_room(cve)
                row = dict(
                    payload={"id": cve, "vendorData": {"id": cve, "evidence": {}, "sources": {}}},
                    families=set(),
                    unwatched_since=None if self.cache.watched(cve) else now,
                    attempted=0,
                )
                self.cache.put(cve, row)
            missing = self.pending(families, row["families"], include_paused=True)
            due = not row["attempted"] or now - row["attempted"] >= HOUR
            manual = force and now - row["attempted"] >= 60
            pending.clear()
            if due or manual or missing:
                kind = "scheduled" if not touch else "manual" if manual and not due else "on_demand"
                self.stats.incr(f"refresh.{kind}")
                # Full refresh: every covered or requested source; otherwise only the missing ones (the hourly
                # clock is unchanged).
                full = due or manual
                targets = (row["families"] | families | {RECORD}) if full else missing
                pending.update(targets)
                # Paused sources answer at once without contacting upstream; they need no refresh slot.
                slot = self.capacity if any(not self.paused(source) for source in targets) else nullcontext()
                async with slot:
                    await self.refresh(cve, row, targets, full=full, publish=publish, pending=pending)
            return self.respond(cve, row["payload"], row["attempted"], created, now)

    def respond(self, cve, payload, attempted, created, now, timeout=False):
        result = copy.deepcopy(payload)
        empty = not result.get("record") and not any(result["vendorData"]["evidence"].values())
        if empty and created and not self.cache.watched(cve):
            # Failed lookups are not stored, so unknown IDs cannot fill the cache.
            self.cache.delete(cve)
        current = self.cache.peek(cve)
        lifecycle = current["unwatched_since"] if current else now
        result["cache"] = {
            "watched": lifecycle is None,
            "expiresAt": int((lifecycle + RETENTION) * 1000) if lifecycle is not None else None,
            "lastAttempt": int(attempted * 1000),
            "retentionDays": RETENTION_DAYS,
            "refreshAfter": int((attempted + 60) * 1000),
        }
        if empty:
            if timeout:
                raise HTTPException(504, "The sources did not answer in time. Try again later.")
            raise HTTPException(
                404 if result.get("notFound") else 502,
                result.get("error", "No CVE or vendor data could be retrieved. Try again later."),
            )
        return result

    def partial(self, cve, pending, touch=True):
        """What is stored for ``cve`` after a deadline, with a timeout error only for work unfinished in this lookup."""
        if not touch and not self.cache.watched(cve):
            return None
        now = self.clock()
        row = self.cache.get(cve)
        if not row:
            raise HTTPException(504, "The sources did not answer in time. Try again later.")
        payload = row["payload"]
        sources = payload["vendorData"]["sources"]
        timed_out = {"attempted": int(now * 1000)}
        for family in sorted(pending - {RECORD}):
            previous = {k: v for k, v in sources.get(family, {}).items() if k != "retryAfter"}
            sources[family] = {**previous, "error": "Vendor source unavailable: request timed out", **timed_out}
        if RECORD in pending:
            payload["error"] = "CVE source unavailable: request timed out"
        return self.respond(cve, payload, row["attempted"], False, now, timeout=True)

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

    async def refresh(self, cve, row, sources, full=True, publish=None, pending=None):
        payload, covered = row["payload"], row["families"]
        families = sorted(set(sources) - {RECORD})
        fetch_record = full or RECORD in sources or not payload.get("record")

        async def area(name, work):
            return name, await self.fetch(name, work)

        jobs = [asyncio.create_task(area(RECORD, lambda: self.providers.record(cve)))] if fetch_record else []
        jobs += [
            asyncio.create_task(area(family, lambda family=family: self.providers.vendor(family, cve)))
            for family in families
        ]
        try:
            for job in asyncio.as_completed(jobs):
                name, result = await job
                now = self.clock()
                answered = not isinstance(result, Exception) or isinstance(result, NotPublished)
                if name == RECORD:
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
                # Only a stored answer makes a source current; failures and pauses are retried.
                if answered:
                    covered.add(name)
                else:
                    covered.discard(name)
                self.cache.put(cve, row)
                if pending is not None:
                    pending.discard(name)
                if publish:
                    publish(copy.deepcopy(payload))
        finally:
            for job in jobs:
                if not job.done():
                    job.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)
        if full:
            row["attempted"] = self.clock()
        self.cache.put(cve, row)

    async def refresh_due(self):
        """Refresh due watched cases, least recently refreshed first, ``SCHEDULED_CONCURRENCY`` at a time."""
        now = self.clock()
        due = iter(
            [
                (cve, families)
                for cve, families, covered, attempted in self.cache.watched_cases()
                if self.due(families, covered, attempted, now)
            ]
        )

        async def runner():
            for cve, families in due:
                self.beat = time.monotonic()
                try:
                    await self.get(cve, families, touch=False, deadline=CASE_DEADLINE)
                except HTTPException:
                    pass  # Source failures are retained and retried once their backoff allows.
                except Exception:
                    logger.exception("Scheduled refresh failed")
                self.beat = time.monotonic()

        await asyncio.gather(*(runner() for _ in range(SCHEDULED_CONCURRENCY)))

    async def maintain(self):
        """Retention and housekeeping, independent of the refresh loop."""
        now = self.clock()
        self.prune()
        if dropped := self.cache.prune_workspaces(
            now - self.settings.workspace_ttl_days * 86400, now, batch=WORKSPACE_BATCH
        ):
            logger.info("Removed %d inactive workspace(s)", dropped)
        self.stats.flush()
        await asyncio.to_thread(logs.maintain)

    async def tick(self):
        await self.maintain()
        await self.refresh_due()

    async def worker(self):
        await loop(self, self.refresh_due, "Background refresh")

    async def maintenance_worker(self):
        await loop(self.maintenance, self.maintain, "Maintenance")


class Heartbeat:
    beat = None


async def loop(owner, step, label):
    while True:
        owner.beat = time.monotonic()
        try:
            await step()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("%s failed", label)
        owner.beat = time.monotonic()
        await asyncio.sleep(PAUSE)


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
# Heartbeat age (seconds) after which a background loop counts as stalled: its longest single step plus the pause
# between iterations, with a margin. The refresh loop beats before and after every case (each under CASE_DEADLINE).
STALL_AFTER = {
    "refresh": CASE_DEADLINE + PAUSE + STALL_MARGIN,
    "maintenance": PAUSE + STALL_MARGIN,
    "tmds-agents": Inventory.step_deadline + Inventory.pause + STALL_MARGIN,
    "tmds-ksp": KernelSupport.step_deadline + KernelSupport.pause + STALL_MARGIN,
}


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
                workers["maintenance"] = (service.maintenance, asyncio.create_task(service.maintenance_worker()))
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

    # API_DOCS exposes only the OpenAPI schema: Swagger UI and ReDoc would load third-party assets.
    app = FastAPI(
        title="Is It Fixed",
        version=settings.version,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.api_docs else None,
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
    app.add_middleware(SecurityHeaders, connect_src=settings.csp_connect_src, hsts=settings.hsts)

    def limit(request, budget, per_minute, detail, global_per_minute=0):
        client = limiter.client_key(client_address(request.scope))
        wait = limiter.hit(budget, client, per_minute)
        if not wait and (wait := limiter.hit(f"{budget}-global", "", global_per_minute)):
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
        """200 "ok"/"degraded" (upstream sources failing) or 503 "stalled" (a background loop is stuck or dead)."""
        response.headers["Cache-Control"] = "no-store"
        now = time.monotonic()
        workers, stalled = {}, []
        for name, (owner, task) in getattr(app.state, "workers", {}).items():
            age = None if owner.beat is None else round(now - owner.beat, 1)
            workers[name] = age
            if task.done() or (age is not None and age > STALL_AFTER[name]):
                stalled.append(name)
        failing = []
        if breaker := getattr(app.state, "breaker", None):
            failing = [name for name, state in sorted(breaker.sources.items()) if state.failures]
        status = "stalled" if stalled else "degraded" if failing else "ok"
        if stalled:
            response.status_code = 503
        return {
            "status": status,
            "version": settings.version,
            "workers": workers,
            "stalled": stalled,
            "failingSources": failing,
            "retentionDays": RETENTION_DAYS,
        }

    @app.put("/api/workspaces/{workspace}/watches")
    async def watches(request: Request, body: Watchlist, workspace: str = APIPath(pattern=r"^[a-f0-9-]{36}$")):
        limit(request, "watches", settings.rate_limit_watches, "Too many watch updates. Try again in {wait} seconds.")
        entries = {entry.id: entry.model_dump() for entry in body.cases}
        service = app.state.service
        limits = {
            "per_workspace": settings.max_watches_per_workspace,
            "watched_cves": settings.max_watched_cves,
            "watch_rows": settings.max_watch_rows,
            "workspaces": settings.max_workspaces,
        }
        try:
            service.cache.replace_watches(workspace, list(entries.values()), service.clock(), limits)
        except CapacityError as error:
            if stats := getattr(app.state, "stats", None):
                stats.incr(f"capacity.{'workspace' if error.status == 422 else 'server'}")
            headers = {"Retry-After": "3600"} if error.status == 429 else None
            raise HTTPException(error.status, error.detail, headers=headers) from None
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
        result = await app.state.service.get(cve, selected, refresh, deadline=LOOKUP_DEADLINE)
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
            # Every progress snapshot is a complete payload, so a slow client only gets the latest one: at most one
            # pending snapshot plus the final result are held per stream.
            state = {"snapshot": None, "final": None, "done": False}
            ready = asyncio.Event()

            def publish(payload):
                state["snapshot"] = payload
                ready.set()

            async def run():
                try:
                    state["final"] = await app.state.service.get(
                        cve, selected, refresh, publish=publish, deadline=LOOKUP_DEADLINE
                    )
                except HTTPException as error:
                    state["final"] = {"error": str(error.detail), "failed": True}
                except Exception:
                    logger.exception("Progressive lookup failed")
                    state["final"] = {"error": "Source lookup failed. Try again later.", "failed": True}
                finally:
                    state["done"] = True
                    ready.set()

            task = asyncio.create_task(run())
            try:
                while True:
                    await ready.wait()
                    ready.clear()
                    if (snapshot := state["snapshot"]) is not None:
                        state["snapshot"] = None
                        yield json.dumps(snapshot) + "\n"
                    if state["done"]:
                        if state["final"] is not None:
                            yield json.dumps(state["final"]) + "\n"
                        break
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
