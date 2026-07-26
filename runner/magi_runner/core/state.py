from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class LocalState:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "state.json"
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.save({"completed_jobs": [], "failed_result_spool": []})

    def load(self) -> dict[str, Any]:
        with self.lock:
            with self.path.open("r", encoding="utf-8") as fh:
                return json.load(fh)

    def save(self, data: dict[str, Any]) -> None:
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            tmp.replace(self.path)

    def mark_completed(self, job_id: str) -> None:
        data = self.load()
        completed = set(data.get("completed_jobs", []))
        completed.add(job_id)
        data["completed_jobs"] = sorted(completed)
        self.save(data)

    def is_completed(self, job_id: str) -> bool:
        return job_id in set(self.load().get("completed_jobs", []))
