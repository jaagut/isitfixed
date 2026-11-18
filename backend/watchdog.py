"""Exit the process when the event loop stops making progress, so the container runtime restarts it."""

import asyncio
import logging
import os
import threading
import time

logger = logging.getLogger("cve-desk.watchdog")


class Watchdog:
    def __init__(self, timeout=120, interval=5, exit=os._exit, clock=time.monotonic):
        self.timeout, self.interval, self.exit, self.clock = timeout, interval, exit, clock
        self.beat = clock()
        self.stopped = threading.Event()

    async def heartbeat(self):
        while True:
            self.beat = self.clock()
            await asyncio.sleep(self.interval)

    def check(self):
        stuck = self.clock() - self.beat
        if stuck > self.timeout:
            logger.critical("Event loop unresponsive for %.0f seconds; exiting for a restart", stuck)
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
