from __future__ import annotations

from typing import Any

import psutil


class NetworkCollector:
    def collect(self) -> list[dict[str, Any]]:
        connections: list[dict[str, Any]] = []
        for conn in psutil.net_connections(kind="inet"):
            try:
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                })
            except Exception:
                continue
        return connections
