from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


def candidate_binaries(configured_path: str | None = None) -> list[str]:
    values = [
        configured_path,
        os.environ.get("MAGI_NUCLEI_PATH"),
        shutil.which("nuclei"),
        r"C:\Program Files\Magi\Runner\tools\nuclei\nuclei.exe",
        r"C:\Program Files\Magi Runner\tools\nuclei\nuclei.exe",
    ]
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(str(value))
    return result


def nuclei_capability(configured_path: str | None = None, templates_path: str | None = None) -> dict[str, Any]:
    searched = candidate_binaries(configured_path)
    binary = next((p for p in searched if Path(p).is_file()), None)
    templates = (
        templates_path
        or os.environ.get("MAGI_NUCLEI_TEMPLATES")
        or r"C:\Program Files\Magi\Runner\tools\nuclei\templates"
    )
    templates_ok = Path(templates).is_dir()
    return {
        "engine": "ready" if binary else "unavailable",
        "engine_available": bool(binary),
        "binary_path": binary,
        "searched_paths": searched,
        "templates": "ready" if templates_ok else "unavailable",
        "templates_available": templates_ok,
        "templates_path": templates,
        "ready": bool(binary and templates_ok),
    }
