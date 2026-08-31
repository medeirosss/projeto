from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .artifacts import sha256_file, safe_name


class FileCollector:
    def collect(self, paths: list[str], job_dir: Path) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        dest_dir = job_dir / "collected_files"
        dest_dir.mkdir(parents=True, exist_ok=True)
        for raw in paths or []:
            p = Path(raw)
            item: dict[str, Any] = {"path": str(p), "exists": p.exists()}
            try:
                if p.is_file():
                    stat = p.stat()
                    copied = dest_dir / safe_name(p.name)
                    shutil.copy2(p, copied)
                    item.update({
                        "type": "file",
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "sha256": sha256_file(p),
                        "copied_to": str(copied.name),
                    })
                elif p.is_dir():
                    item.update({"type": "directory", "children": [str(x) for x in p.iterdir()]})
            except Exception as exc:
                item["error"] = str(exc)
            out.append(item)
        return out
