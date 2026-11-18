"""Per-source circuit breaker: back off exponentially after consecutive upstream failures."""

import time
from dataclasses import dataclass

from .errors import Busy, NotPublished, Paused, describe, log_failure

MINUTE = 60
MAX_DELAY = 30 * MINUTE


@dataclass
class SourceState:
    failures: int = 0
    paused_until: float = 0.0
    last_error: str | None = None
    last_error_at: float | None = None
    last_success_at: float | None = None


class Breaker:
    """Tracks consecutive failures per source.

    After ``threshold`` consecutive failures the source is paused for 1 minute, then 2, 4, … up to 30 minutes for
    every further failure. A success resets the source. ``NotPublished`` (HTTP 404) is a valid answer, not a failure.
    """

    def __init__(self, clock=time.time, threshold=3, thresholds=None):
        self.clock, self.threshold, self.thresholds = clock, threshold, thresholds or {}
        self.sources: dict[str, SourceState] = {}

    def state(self, source):
        return self.sources.setdefault(source, SourceState())

    def check(self, source):
        """Raise ``Paused`` when the source is backing off."""
        state = self.sources.get(source)
        if state and state.paused_until > self.clock():
            raise Paused(state.paused_until)

    def retry_after(self, source):
        state = self.sources.get(source)
        return state.paused_until if state and state.paused_until > self.clock() else None

    def success(self, source):
        state = self.state(source)
        state.failures, state.paused_until, state.last_success_at = 0, 0.0, self.clock()

    def record(self, source, result):
        """Record a completed attempt; ``result`` is the returned value or the raised exception."""
        if isinstance(result, (Paused, Busy)):
            return  # upstream was not (fully) contacted: neither a success nor a source failure
        if isinstance(result, NotPublished) or not isinstance(result, BaseException):
            self.success(source)
            return
        log_failure(source, result)
        state = self.state(source)
        now = self.clock()
        state.failures += 1
        state.last_error, state.last_error_at = describe(result), now
        threshold = self.thresholds.get(source, self.threshold)
        if state.failures >= threshold:
            state.paused_until = now + min(MINUTE * 2 ** min(state.failures - threshold, 10), MAX_DELAY)

    def snapshot(self):
        now = self.clock()
        return {
            name: {
                "consecutiveFailures": state.failures,
                "pausedUntil": int(state.paused_until * 1000) if state.paused_until > now else None,
                "lastError": state.last_error,
                "lastErrorAt": int(state.last_error_at * 1000) if state.last_error_at else None,
                "lastSuccessAt": int(state.last_success_at * 1000) if state.last_success_at else None,
            }
            for name, state in sorted(self.sources.items())
        }
