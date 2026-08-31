from __future__ import annotations

from typing import Any, Dict

import requests

from app.config import REQUEST_TIMEOUT, SECURITY_BACKEND_URL
from app.services.settings_service import is_security_enabled, is_uem_enabled


def get_module_status(settings: Dict[str, Any]) -> Dict[str, Any]:
    uem_enabled = is_uem_enabled(settings)
    security_enabled = is_security_enabled(settings)
    security_online = False
    security_error = None

    if security_enabled:
        try:
            response = requests.get(f"{SECURITY_BACKEND_URL}/health", timeout=min(REQUEST_TIMEOUT, 5))
            security_online = response.ok
            if not response.ok:
                security_error = f"status={response.status_code}"
        except Exception as exc:
            security_error = str(exc)

    return {
        "uem": {
            "label": "UEM",
            "enabled": uem_enabled,
            "online": uem_enabled,
            "source": "local",
        },
        "security": {
            "label": "Security",
            "enabled": security_enabled,
            "online": security_enabled and security_online,
            "source": SECURITY_BACKEND_URL,
            "error": security_error,
        },
    }
