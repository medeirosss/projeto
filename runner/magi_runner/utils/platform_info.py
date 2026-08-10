from __future__ import annotations

import getpass
import platform
import socket
import time
from typing import Any

import psutil

from magi_runner.executors.nmap_discovery import nmap_capability


def get_host_info(active_jobs: int = 0) -> dict[str, Any]:
    addrs = []
    for iface, values in psutil.net_if_addrs().items():
        for addr in values:
            if getattr(addr, "family", None) == socket.AF_INET:
                addrs.append({"interface": iface, "ip": addr.address})

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "user": getpass.getuser(),
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "boot_time": psutil.boot_time(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "ips": addrs,
        "active_jobs": active_jobs,
        "capabilities": {"nmap_discovery": nmap_capability(), "service_discovery": nmap_capability(), "credential_validate": {"available": True, "max_attempts_per_host": 2}},
    }
