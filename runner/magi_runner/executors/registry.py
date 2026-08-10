from __future__ import annotations

from typing import Any

from .atomic import AtomicExecutor
from .cmd import CmdExecutor
from .powershell import PowerShellExecutor
from .python_exec import PythonExecutor
from .nmap_discovery import NmapDiscoveryExecutor
from .service_discovery import ServiceDiscoveryExecutor
from .credential_validate import CredentialValidateExecutor
from .deep_inventory import DeepInventoryExecutor


class ExecutorRegistry:
    def __init__(self, allowed: list[str]) -> None:
        executors = [CmdExecutor(), PowerShellExecutor(), PythonExecutor(), AtomicExecutor(), NmapDiscoveryExecutor(), ServiceDiscoveryExecutor(), CredentialValidateExecutor(), DeepInventoryExecutor()]
        self._executors = {e.name: e for e in executors if e.name in allowed}
        self._executors["ps"] = self._executors.get("powershell")
        self._executors["pwsh"] = self._executors.get("powershell")
        self._executors["shell"] = self._executors.get("cmd")
        self._executors["atomic_validation"] = self._executors.get("atomic")
        self._executors = {k: v for k, v in self._executors.items() if v is not None}

    def get(self, name: str) -> Any:
        if name not in self._executors:
            raise ValueError(f"Executor not allowed or unknown: {name}")
        return self._executors[name]
