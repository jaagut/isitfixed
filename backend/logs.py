"""Logging: UTC timestamps, no client addresses, WARNING+ on stdout, optional daily files in LOG_DIR.

Retention is age based and enforced by the app itself: the active file is rotated at midnight UTC (by the maintenance
loop, even when nothing is logged) and files older than LOG_RETENTION_DAYS are deleted.
"""

import logging
import re
import sys
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from .errors import scrub

LOG_FILE = "isitfixed.log"
FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
# Include pre-rebrand logs in retention so upgrades never leave old files behind.
LEGACY_LOG_FILE = "cve-desk.log"
ROTATED = re.compile(rf"^(?:{re.escape(LOG_FILE)}|{re.escape(LEGACY_LOG_FILE)})\.(\d{{4}}-\d{{2}}-\d{{2}})(?:\.\d+)?$")

_handler = None  # the active DailyFileHandler, for the maintenance loop


class UTCFormatter(logging.Formatter):
    converter = time.gmtime
    default_time_format = "%Y-%m-%dT%H:%M:%S"
    default_msec_format = "%s.%03dZ"


class Redact(logging.Filter):
    """Last line of defence: strip IP addresses from every record."""

    def filter(self, record):
        message = record.getMessage()
        cleaned = scrub(message)
        if cleaned != message:
            record.msg, record.args = cleaned, None
        return True


def _day(timestamp):
    return datetime.fromtimestamp(timestamp, UTC).date()


def remove_old_logs(directory, days, now=None):
    """Delete rotated files older than ``days`` days (by the date in their name, else by modification time).

    The active file plus ``days - 1`` rotated files cover the retention period.
    """
    now = time.time() if now is None else now
    oldest_kept = _day(now) - timedelta(days=days - 1)
    for path in (*Path(directory).glob(f"{LOG_FILE}*"), *Path(directory).glob(f"{LEGACY_LOG_FILE}*")):
        if path.name == LOG_FILE:
            continue
        try:
            match = ROTATED.match(path.name)
            expired = date.fromisoformat(match[1]) < oldest_kept if match else path.stat().st_mtime < now - days * 86400
            if expired and path.is_file():
                path.unlink()
        except (OSError, ValueError):
            pass


class DailyFileHandler(logging.FileHandler):
    """Writes ``isitfixed.log`` and renames it to ``isitfixed.log.YYYY-MM-DD`` when the UTC day changes."""

    def __init__(self, directory, retention_days, clock=time.time):
        self.directory, self.retention_days, self.clock = Path(directory), retention_days, clock
        path = self.directory / LOG_FILE
        # A file left from an earlier day (e.g. the process was down at midnight) is rotated first.
        self.day = _day(path.stat().st_mtime) if path.exists() else _day(clock())
        super().__init__(path, encoding="utf-8", delay=True)
        self.rotate_if_due()

    def rotate_if_due(self):
        """Rotate when the UTC day has changed and delete expired files; safe to call from any thread."""
        today = _day(self.clock())
        self.acquire()  # the handler's re-entrant lock, also held while emitting
        try:
            if today != self.day:
                if self.stream:
                    self.stream.close()
                    self.stream = None
                current = Path(self.baseFilename)
                if current.exists():
                    target = current.with_name(f"{LOG_FILE}.{self.day.isoformat()}")
                    suffix = 1
                    while target.exists():
                        target = current.with_name(f"{LOG_FILE}.{self.day.isoformat()}.{suffix}")
                        suffix += 1
                    current.rename(target)
                self.day = today
        finally:
            self.release()
        remove_old_logs(self.directory, self.retention_days, self.clock())

    def emit(self, record):
        if _day(self.clock()) != self.day:
            self.rotate_if_due()
        super().emit(record)


def maintain():
    """Daily rotation and age-based deletion (called by the app's maintenance loop; a no-op without LOG_DIR)."""
    if _handler is not None:
        _handler.rotate_if_due()


def configure(settings, clock=time.time):
    global _handler
    formatter = UTCFormatter(FORMAT)
    redact = Redact()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.WARNING)
    handlers = [console]
    _handler = None
    if settings.log_dir:
        directory = Path(settings.log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        _handler = DailyFileHandler(directory, settings.log_retention_days, clock)
        _handler.setLevel(settings.log_level)
        handlers.append(_handler)
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(redact)
        root.addHandler(handler)
    root.setLevel(min(logging.getLevelName(settings.log_level), logging.WARNING))
    # Uvicorn's own handlers are disabled (log_config=None); its records propagate here. No access log.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    # httpx logs every request URL at INFO; keep it quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
