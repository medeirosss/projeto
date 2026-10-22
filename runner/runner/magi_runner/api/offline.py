from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from magi_runner.core.state import LocalState


class OfflineJobSource:
    def __init__(self, jobs_file: str, state: LocalState) -> None:
        self.jobs_file = Path(jobs_file)
        self.state = state

    def get_job(self) -> dict[str, Any] | None:
        if not self.jobs_file.exists():
            return None
        jobs = json.loads(self.jobs_file.read_text(encoding="utf-8"))
        for job in jobs:
            job_id = str(job.get("job_id"))
            if job_id and not self.state.is_completed(job_id):
                return job
        return None
