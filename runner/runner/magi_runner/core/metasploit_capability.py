from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

_CACHE: dict[str, Any] = {"at": 0.0, "value": None}
CACHE_TTL_SECONDS = 300

KNOWN_WINDOWS_PATHS = [
    r"C:\metasploit-framework\bin\msfconsole.bat",
    r"C:\metasploit-framework\msfconsole.bat",
]

def find_msfconsole(explicit_path: str | None = None) -> str | None:
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)
    env_path = os.getenv("MAGI_METASPLOIT_PATH")
    if env_path:
        candidates.append(env_path)
    for command in ("msfconsole", "msfconsole.bat"):
        found = shutil.which(command)
        if found:
            candidates.append(found)
    if os.name == "nt":
        candidates.extend(KNOWN_WINDOWS_PATHS)
    for candidate in candidates:
        try:
            p = Path(candidate)
            if p.exists() and p.is_file():
                return str(p.resolve())
        except Exception:
            continue
    return None

def metasploit_capability(explicit_path: str | None = None, timeout: int = 20, refresh: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    if not refresh and _CACHE.get("value") is not None and (now - float(_CACHE.get("at") or 0)) < CACHE_TTL_SECONDS:
        return dict(_CACHE["value"])
    path = find_msfconsole(explicit_path)
    if not path:
        value = {
            "available": False,
            "provider": "metasploit",
            "path": None,
            "version": None,
            "message": "msfconsole não encontrado. Configure metasploit_path/MAGI_METASPLOIT_PATH ou instale o Metasploit no PATH.",
        }
        _CACHE.update({"at": now, "value": value})
        return dict(value)
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        m = re.search(r"(?:Framework|Metasploit Framework)[: ]+([^\r\n]+)", output, re.I)
        version = (m.group(1).strip() if m else (output.splitlines()[0].strip() if output else "unknown"))
        value = {
            "available": proc.returncode == 0,
            "provider": "metasploit",
            "path": path,
            "version": version,
            "returncode": proc.returncode,
            "message": output[-2000:],
        }
        _CACHE.update({"at": now, "value": value})
        return dict(value)
    except Exception as exc:
        value = {"available": False, "provider": "metasploit", "path": path, "version": None, "message": str(exc)}
        _CACHE.update({"at": now, "value": value})
        return dict(value)
