"""Entry point: ``python -m backend`` runs the public app and the private admin dashboard in one event loop."""

import asyncio
import contextlib
import logging
import signal
import sys

import uvicorn

from . import logs
from .admin import create_admin_app
from .main import create_app
from .settings import Settings, SettingsError
from .watchdog import Watchdog

logger = logging.getLogger("cve-desk")


class Server(uvicorn.Server):
    """A uvicorn server whose shutdown is driven by this module's signal handlers."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def config(app, settings, port, **kwargs):
    return uvicorn.Config(
        app,
        host=settings.host,
        port=port,
        log_config=None,
        access_log=False,
        server_header=False,
        timeout_graceful_shutdown=20,
        **kwargs,
    )


async def serve(settings):
    public = create_app(settings=settings)
    servers = [
        Server(
            config(
                public,
                settings,
                settings.port,
                proxy_headers=True,
                forwarded_allow_ips=settings.forwarded_allow_ips,
                lifespan="on",
            )
        )
    ]
    if settings.admin_port:
        admin = create_admin_app(public, settings)
        servers.append(Server(config(admin, settings, settings.admin_port, proxy_headers=False, lifespan="off")))

    def stop(*_):
        for server in servers:
            server.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    watchdog = Watchdog(settings.watchdog_timeout) if settings.watchdog_timeout else None
    heartbeat = asyncio.create_task(watchdog.heartbeat()) if watchdog else None
    if watchdog:
        watchdog.start()
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    failed = False
    try:
        # When one server stops (signal or startup failure), stop the other one as well.
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        stop()
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, BaseException):
                failed = True
                if not isinstance(result, SystemExit):
                    logger.error("Server failed", exc_info=result)
    finally:
        if watchdog:
            watchdog.stop()
            heartbeat.cancel()
    # A startup failure (e.g. port in use) exits non-zero so the container restarts.
    return 1 if failed or any(not server.started for server in servers) else 0


def main():
    try:
        settings = Settings.from_env()
    except SettingsError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    logs.configure(settings)
    return asyncio.run(serve(settings))


if __name__ == "__main__":
    sys.exit(main())
