from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class Watchdog:
    """Small local watchdog/health reporter.

    It does not restart the OS service. Recovery is delegated to Windows Service
    recovery options or systemd Restart=always. This component writes a health
    file that can be inspected by support and by future backend checks.
    """

    def __init__(self, data_path: Path, logger, interval_seconds: int = 30) -> None:
        self.data_path = data_path
        self.logger = logger
        self.interval_seconds = max(10, interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_loop_ts = time.time()
        self.health_file = self.data_path / "health.json"

    def beat(self) -> None:
        self._last_loop_ts = time.time()

    def start(self) -> None:
        self.data_path.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._run, name="magi-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            payload: dict[str, Any] = {
                "status": "running",
                "pid": os.getpid(),
                "last_loop_at": self._last_loop_ts,
                "last_loop_age_seconds": round(time.time() - self._last_loop_ts, 2),
                "updated_at": time.time(),
            }
            try:
                self.health_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            except Exception as exc:  # pragma: no cover
                self.logger.warning("Failed to write health file: %s", exc)
            self._stop.wait(self.interval_seconds)
