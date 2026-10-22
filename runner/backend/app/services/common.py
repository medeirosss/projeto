from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import LOGS_DIR


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def save_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def write_text_log(prefix: str, text: str) -> Path:
    path = LOGS_DIR / f"{prefix}({now_stamp()}).log"
    path.write_text(text, encoding="utf-8")
    return path


def normalize_hostname(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().upper()
    if not text:
        return ""
    if "." in text:
        text = text.split(".")[0].strip()
    return text


def list_to_text(value: Any) -> str:
    if value is None:
        return "--"
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(items) if items else "--"
    text = str(value).strip()
    return text if text else "--"
