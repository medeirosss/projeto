from __future__ import annotations

import platform
import subprocess
from typing import Any


class EventLogCollector:
    def collect(self, channels: list[str] | None = None, max_events: int = 30) -> dict[str, Any]:
        if platform.system().lower() != "windows":
            return {"supported": False, "reason": "Windows Event Log collection is only available on Windows"}
        channels = channels or ["System", "Application"]
        result: dict[str, Any] = {"supported": True, "channels": {}}
        for channel in channels:
            try:
                cmd = ["wevtutil", "qe", channel, "/c:" + str(max_events), "/f:text", "/rd:true"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                result["channels"][channel] = {"exit_code": proc.returncode, "stdout": proc.stdout[-20000:], "stderr": proc.stderr}
            except Exception as exc:
                result["channels"][channel] = {"error": str(exc)}
        return result
