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
        else:
            data = self.load()
            changed = False
            if "completed_jobs" not in data:
                data["completed_jobs"] = []
                changed = True
            if "failed_result_spool" not in data:
                data["failed_result_spool"] = []
                changed = True
            if changed:
                self.save(data)

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
        completed = set(str(x) for x in data.get("completed_jobs", []))
        completed.add(str(job_id))
        data["completed_jobs"] = sorted(completed)
        self.save(data)

    def is_completed(self, job_id: str) -> bool:
        return str(job_id) in set(str(x) for x in self.load().get("completed_jobs", []))

    def spool_result(self, job_id: str, result: dict[str, Any]) -> None:
        """Persist a result until the backend acknowledges it.

        One entry per job_id is kept; a newer result replaces the older copy.
        """
        data = self.load()
        spool = [
            item for item in data.get("failed_result_spool", [])
            if str(item.get("job_id")) != str(job_id)
        ]
        spool.append({"job_id": str(job_id), "result": result})
        data["failed_result_spool"] = spool
        self.save(data)

    def list_spooled_results(self) -> list[dict[str, Any]]:
        return list(self.load().get("failed_result_spool", []))

    def remove_spooled_result(self, job_id: str) -> None:
        data = self.load()
        data["failed_result_spool"] = [
            item for item in data.get("failed_result_spool", [])
            if str(item.get("job_id")) != str(job_id)
        ]
        self.save(data)
