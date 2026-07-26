from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from magi_runner.api.client import MagiApiClient
from magi_runner.utils.platform_info import get_host_info


class HeartbeatThread(threading.Thread):
    daemon = True

    def __init__(self, api: MagiApiClient, interval: int, active_jobs_fn: Callable[[], int], logger: logging.Logger) -> None:
        super().__init__()
        self.api = api
        self.interval = interval
        self.active_jobs_fn = active_jobs_fn
        self.logger = logger.getChild("heartbeat")
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.api.heartbeat(get_host_info(active_jobs=self.active_jobs_fn()))
                self.logger.debug("Heartbeat sent")
            except Exception as exc:
                self.logger.warning("Heartbeat failed: %s", exc)
            self.stop_event.wait(self.interval)
