"""Exit the process when the event loop stops making progress, so the container runtime restarts it."""

import asyncio
import os
import threading
import time

from .settings import WATCHDOG_INTERVAL


def _report(stuck):
    # No logging here: a handler lock held by the stuck loop thread could block the exit forever.
    message = f"CRITICAL isitfixed.watchdog: event loop unresponsive for {stuck:.0f} seconds; exiting for a restart\n"
    try:
        os.write(2, message.encode())
    except OSError:
        pass


class Watchdog:
    def __init__(self, timeout=120, interval=WATCHDOG_INTERVAL, exit=os._exit, clock=time.monotonic, report=_report):
        self.timeout, self.interval, self.exit, self.clock, self.report = timeout, interval, exit, clock, report
        self.beat = clock()
        self.stopped = threading.Event()

    async def heartbeat(self):
        while True:
            self.beat = self.clock()
            await asyncio.sleep(self.interval)

    def check(self):
        stuck = self.clock() - self.beat
        if stuck > self.timeout:
            self.report(stuck)
            self.exit(1)
            return False
        return True

    def watch(self):
        while not self.stopped.wait(self.interval):
            if not self.check():
                return

    def start(self):
        thread = threading.Thread(target=self.watch, name="watchdog", daemon=True)
        thread.start()
        return thread

    def stop(self):
        self.stopped.set()
