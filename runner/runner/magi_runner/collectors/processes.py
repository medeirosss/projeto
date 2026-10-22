from __future__ import annotations

from typing import Any

import psutil


class ProcessCollector:
    def collect(self) -> list[dict[str, Any]]:
        processes: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "create_time", "status"]):
            try:
                info = proc.info
                processes.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "username": info.get("username"),
                    "cmdline": info.get("cmdline"),
                    "create_time": info.get("create_time"),
                    "status": info.get("status"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
