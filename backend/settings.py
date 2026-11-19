"""Runtime settings, read once from environment variables (see docs/deployment.md)."""

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _version():
    # pyproject.toml is the single place where the version is defined; the image ships it next to the backend.
    try:
        return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return "0.0.0"


VERSION = _version()
DEFAULT_SOURCE_URL = "https://github.com/jaagut/isitfixed"
# Fallback "last updated" date of the bundled legal templates.
LEGAL_TEMPLATES_UPDATED = "2026-11-18"
MAX_LOG_RETENTION_DAYS = 14
# The watchdog heartbeat runs every WATCHDOG_INTERVAL seconds; WATCHDOG_TIMEOUT must cover several missed beats.
WATCHDOG_INTERVAL = 5

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class SettingsError(ValueError):
    """An environment variable has an invalid value."""


@dataclass(frozen=True)
class Settings:
    version: str = VERSION
    # Storage and serving
    cache_db: str = str(ROOT / "data" / "cache.sqlite3")
    serve_frontend: bool = True
    frontend_dir: Path = ROOT
    cors_origins: tuple[str, ...] = ()
    host: str = "127.0.0.1"
    port: int = 8080
    # Features
    manual_refresh: bool = False
    tmds_enabled: bool = True
    api_docs: bool = False
    # Capacity and retention
    max_watched_cves: int = 1000
    # Must exceed max_watched_cves, so lookups of unwatched CVEs always find a cache slot.
    max_cached_cves: int = 1500
    max_watches_per_workspace: int = 200
    max_workspaces: int = 5000
    max_watch_rows: int = 50000
    workspace_ttl_days: int = 30
    # Rate limits per shortened client address (IPv4 /24, IPv6 /48) and minute; 0 disables a budget
    rate_limit_requests: int = 300
    rate_limit_lookups: int = 30
    rate_limit_lookups_global: int = 120
    rate_limit_watches: int = 12
    forwarded_allow_ips: str = "127.0.0.1"
    # Identity
    source_url: str = DEFAULT_SOURCE_URL
    site_url: str = ""
    user_agent: str = ""
    # Logging
    log_dir: str | None = None
    log_level: str = "INFO"
    log_retention_days: int = MAX_LOG_RETENTION_DAYS
    # Admin dashboard
    # Off unless ADMIN_PORT is set, so the dashboard is never reachable by accident.
    admin_port: int | None = None
    admin_token: str | None = field(default=None, repr=False)
    # Security headers
    hsts: bool = False
    csp_connect_src: tuple[str, ...] = ()
    # Process watchdog: exit when the event loop is stuck for this many seconds (0 disables)
    watchdog_timeout: int = 120
    # Legal pages
    legal_operator_name: str = ""
    legal_operator_address: str = ""
    legal_operator_email: str = ""
    legal_operator_phone: str = ""
    legal_responsible_person: str = ""
    legal_hosting_provider: str = ""
    legal_dir: str | None = None
    legal_access_logs: bool = False
    legal_last_updated: str = LEGAL_TEMPLATES_UPDATED

    def __post_init__(self):
        if not self.user_agent:
            object.__setattr__(self, "user_agent", f"isitfixed/{self.version} (+{self.source_url})")
        object.__setattr__(self, "log_retention_days", max(1, min(self.log_retention_days, MAX_LOG_RETENTION_DAYS)))
        object.__setattr__(self, "frontend_dir", Path(self.frontend_dir))
        if self.max_cached_cves <= self.max_watched_cves:
            raise SettingsError(
                f"MAX_CACHED_CVES ({self.max_cached_cves}) must be greater than MAX_WATCHED_CVES"
                f" ({self.max_watched_cves}), so lookups of unwatched CVEs always find room"
            )
        if 0 < self.watchdog_timeout < 3 * WATCHDOG_INTERVAL:
            raise SettingsError(
                f"WATCHDOG_TIMEOUT must be 0 (off) or at least {3 * WATCHDOG_INTERVAL} seconds"
                f" (three heartbeat intervals of {WATCHDOG_INTERVAL} s)"
            )

    @classmethod
    def from_env(cls, env=None, **overrides):
        env = os.environ if env is None else env
        values = {}

        def text(name, key=None):
            value = env.get(name)
            if value is not None and value.strip():
                values[key or name.lower()] = value.strip()

        def flag(name):
            value = env.get(name, "").strip().lower()
            if value in _TRUE:
                values[name.lower()] = True
            elif value in _FALSE:
                values[name.lower()] = False
            elif value:
                raise SettingsError(f"{name} must be true or false")

        def number(name, minimum=0, key=None):
            value = env.get(name, "").strip()
            if not value:
                return
            try:
                parsed = int(value)
            except ValueError:
                raise SettingsError(f"{name} must be an integer") from None
            if parsed < minimum:
                raise SettingsError(f"{name} must be at least {minimum}")
            values[key or name.lower()] = parsed

        def items(name):
            if name in env:
                values[name.lower()] = tuple(item.strip() for item in env[name].replace(",", " ").split() if item)

        text("CACHE_DB")
        flag("SERVE_FRONTEND")
        text("FRONTEND_DIR")
        items("CORS_ORIGINS")
        text("HOST")
        number("PORT", 1)
        for name in ("MANUAL_REFRESH", "TMDS_ENABLED", "API_DOCS", "HSTS", "LEGAL_ACCESS_LOGS"):
            flag(name)
        for name in (
            "MAX_WATCHED_CVES",
            "MAX_CACHED_CVES",
            "MAX_WATCHES_PER_WORKSPACE",
            "MAX_WORKSPACES",
            "MAX_WATCH_ROWS",
            "WORKSPACE_TTL_DAYS",
        ):
            number(name, 1)
        for name in ("REQUESTS", "LOOKUPS", "LOOKUPS_GLOBAL", "WATCHES"):
            number(f"RATE_LIMIT_{name}")
        text("FORWARDED_ALLOW_IPS")
        for name in ("SOURCE_URL", "SITE_URL", "USER_AGENT", "LOG_DIR", "ADMIN_TOKEN"):
            text(name)
        if "LOG_LEVEL" in env and env["LOG_LEVEL"].strip():
            level = env["LOG_LEVEL"].strip().upper()
            if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                raise SettingsError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
            values["log_level"] = level
        number("LOG_RETENTION_DAYS", 1)
        if "ADMIN_PORT" in env:
            port = env["ADMIN_PORT"].strip()
            values["admin_port"] = None
            if port and port != "0":
                number("ADMIN_PORT", 1)
        items("CSP_CONNECT_SRC")
        number("WATCHDOG_TIMEOUT")
        for name in (
            "OPERATOR_NAME",
            "OPERATOR_ADDRESS",
            "OPERATOR_EMAIL",
            "OPERATOR_PHONE",
            "RESPONSIBLE_PERSON",
            "HOSTING_PROVIDER",
            "DIR",
            "LAST_UPDATED",
        ):
            text(f"LEGAL_{name}")
        # Compose files, .env and podman env files cannot hold real newlines easily; accept a literal "\n" in every
        # legal text value (addresses of the operator, the responsible person and the hosting provider).
        for key in (
            "legal_operator_name",
            "legal_operator_address",
            "legal_responsible_person",
            "legal_hosting_provider",
        ):
            if key in values:
                values[key] = values[key].replace("\\n", "\n")
        values.update(overrides)
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in values.items() if k in known})
