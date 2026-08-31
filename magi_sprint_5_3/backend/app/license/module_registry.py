from __future__ import annotations

from typing import Optional

PUBLIC_PATHS = (
    "/license",
    "/license/status",
    "/license/upload",
    "/health",
    "/api/health",
)

MODULE_BY_PATH = {
    "/": "centric",
    "/home": "centric",
    "/centric": "centric",
    "/api/dashboard": "centric",
    "/relatorios": "reports",
    "/api/reports": "reports",
    "/acoes": "actions",
    "/instalador": "actions",
    "/api/actions": "actions",
    "/alertas": "alerts",
    "/api/alerts": "alerts",
    "/configuracoes": "settings",
    "/api/settings": "settings",
    "/api/token": "settings",
}


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/license/")


def module_for_path(path: str) -> Optional[str]:
    matches = sorted(MODULE_BY_PATH.items(), key=lambda item: len(item[0]), reverse=True)
    for prefix, module in matches:
        if path == prefix or path.startswith(prefix + "/"):
            return module
    if path.startswith("/assets"):
        return "centric"
    return None
