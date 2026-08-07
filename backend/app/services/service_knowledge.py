from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

_PATH = Path(__file__).resolve().parents[2] / "config" / "service_knowledge.yaml"
_CACHE: dict[int, dict[str, Any]] | None = None


def _load() -> dict[int, dict[str, Any]]:
    global _CACHE
    if _CACHE is None:
        raw = yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}
        entries = raw.get("services") or {}
        _CACHE = {int(k): dict(v or {}) for k, v in entries.items()}
    return _CACHE


def lookup_service(port: int, protocol: str = "tcp", detected_name: str | None = None) -> dict[str, Any]:
    item = dict(_load().get(int(port), {}))
    friendly = item.get("name") or detected_name or "Unknown"
    return {
        "friendly_name": friendly,
        "category": item.get("category") or "Other",
        "knowledge_match": bool(item),
    }
