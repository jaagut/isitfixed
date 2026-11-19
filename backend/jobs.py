"""Hourly background jobs with persisted status, backoff after failures and exception-safe worker loops."""

import asyncio
import logging
import time

from .errors import describe

HOUR = 3600
logger = logging.getLogger("isitfixed.jobs")


class HourlyJob:
    """Runs ``run()`` hourly; after a failure it retries when the source's backoff allows.

    ``attempted``/``checked`` (last success)/``error`` survive restarts in the ``meta`` table, so a restart
    does not re-download upstream data that is still fresh.
    """

    name = "job"
    interval = HOUR
    pause = 60  # seconds between worker iterations
    step_deadline = 600  # longest a single step (between two heartbeats) may take; bounds the health check

    def __init__(self, cache, client, clock=time.time, breaker=None, stats=None):
        self.cache, self.client, self.clock = cache, client, clock
        self.breaker, self.stats = breaker, stats
        self.lock = asyncio.Lock()
        self.beat = None
        state = cache.get_meta(f"job:{self.name}", {})
        self.attempted = state.get("attempted", 0)
        self.checked = state.get("checked")
        self.error = state.get("error")
        self.extra = state.get("extra", {})

    def due(self):
        if self.lock.locked() or (self.breaker and self.breaker.retry_after(self.name)):
            return False
        return self.error is not None or self.clock() - self.attempted >= self.interval

    async def run(self):
        raise NotImplementedError

    def cleanup(self):
        """Retention pruning; runs after every attempt."""

    def save(self):
        state = {"attempted": self.attempted, "checked": self.checked, "error": self.error, "extra": self.extra}
        self.cache.set_meta(f"job:{self.name}", state)

    def count(self, name):
        if self.stats:
            self.stats.incr(name)

    async def tick(self):
        if not self.due():
            return
        async with self.lock:
            self.attempted = self.clock()
            self.count(f"fetch.{self.name}")
            try:
                await self.run()
            except asyncio.CancelledError:
                self.error = "Refresh interrupted; retry pending"
                raise
            except Exception as error:
                self.error = describe(error)
                self.count(f"failure.{self.name}")
                if self.breaker:
                    self.breaker.record(self.name, error)
            else:
                self.error, self.checked = None, self.clock()
                if self.breaker:
                    self.breaker.success(self.name)
            finally:
                self.cleanup()
                self.save()

    def status(self):
        return {
            "error": self.error,
            "attempted": int(self.attempted * 1000),
            "checked": int(self.checked * 1000) if self.checked else None,
        }

    async def worker(self):
        while True:
            self.beat = time.monotonic()
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("%s worker iteration failed", self.name)
            await asyncio.sleep(self.pause)
