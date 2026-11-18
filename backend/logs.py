"""Logging: UTC timestamps, no client addresses, WARNING+ on stdout, optional daily-rotated files in LOG_DIR."""

import logging
import logging.handlers
import sys
import time
from pathlib import Path

from .errors import scrub

LOG_FILE = "cve-desk.log"
FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


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


def remove_old_logs(directory, days, now=None):
    """Delete rotated log files older than the retention period (e.g. left over from a longer setting)."""
    cutoff = (now or time.time()) - days * 86400
    for path in Path(directory).glob(f"{LOG_FILE}*"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            pass


def configure(settings):
    formatter = UTCFormatter(FORMAT)
    redact = Redact()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.WARNING)
    handlers = [console]
    if settings.log_dir:
        directory = Path(settings.log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        remove_old_logs(directory, settings.log_retention_days)
        file = logging.handlers.TimedRotatingFileHandler(
            directory / LOG_FILE,
            when="midnight",
            utc=True,
            backupCount=max(settings.log_retention_days - 1, 1),
            encoding="utf-8",
        )
        file.setLevel(settings.log_level)
        handlers.append(file)
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
