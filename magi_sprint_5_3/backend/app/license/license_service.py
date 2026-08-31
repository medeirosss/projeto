from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Any, Dict

from app.license.license_validator import validate_license_file

try:
    from app.repositories.license_repository import save_license_status
except Exception:  # pragma: no cover
    save_license_status = None


class LicenseService:
    def __init__(self) -> None:
        self.license_file = Path(os.getenv("LICENSE_FILE", "/app/license/license.json"))
        self.public_key_file = Path(os.getenv("LICENSE_PUBLIC_KEY_FILE", "app/license/public_key.pem"))
        self.enforcement = os.getenv("LICENSE_ENFORCEMENT", "true").lower() == "true"
        self._lock = RLock()
        self._status: Dict[str, Any] = {
            "valid": False,
            "status": "not_checked",
            "status_message": "Licença ainda não validada.",
        }

    def validate(self) -> Dict[str, Any]:
        with self._lock:
            status = validate_license_file(self.license_file, self.public_key_file)
            self._status = status
            if save_license_status:
                try:
                    save_license_status(status)
                except Exception:
                    # Banco pode ainda não estar pronto durante o bootstrap. A licença continua sendo validada em memória.
                    pass
            return dict(self._status)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            public = dict(self._status)
            public.pop("raw_license", None)
            return public

    def is_valid(self) -> bool:
        if not self.enforcement:
            return True
        return bool(self._status.get("valid"))

    def is_module_allowed(self, module: str | None) -> bool:
        if not self.enforcement:
            return True
        if not self.is_valid():
            return False
        if not module:
            return True
        modules = self._status.get("modules") or {}
        return bool(modules.get(module, False))

    def replace_license(self, content: bytes) -> Dict[str, Any]:
        self.license_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.license_file.with_suffix(".upload.tmp")
        temp_file.write_bytes(content)
        status = validate_license_file(temp_file, self.public_key_file)
        if not status.get("valid"):
            temp_file.unlink(missing_ok=True)
            return status
        temp_file.replace(self.license_file)
        return self.validate()


license_service = LicenseService()
