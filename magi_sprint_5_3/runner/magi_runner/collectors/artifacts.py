from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


class ArtifactManager:
    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)

    def create_job_dir(self, job_id: str) -> Path:
        path = self.root / safe_name(job_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_text(self, job_dir: Path, filename: str, content: str) -> Path:
        path = job_dir / filename
        path.write_text(content or "", encoding="utf-8", errors="replace")
        return path

    def write_json(self, job_dir: Path, filename: str, content: Any) -> Path:
        path = job_dir / filename
        path.write_text(json.dumps(content, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return path

    def zip_job_dir(self, job_dir: Path) -> Path:
        zip_base = str(job_dir)
        zip_path = shutil.make_archive(zip_base, "zip", job_dir)
        return Path(zip_path)


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
