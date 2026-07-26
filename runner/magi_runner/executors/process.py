from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Any

from .base import ExecutionResult


def run_subprocess(args: list[str], workdir: str, timeout_seconds: int, shell: bool = False) -> ExecutionResult:
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            args if not shell else " ".join(args),
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=shell,
        )
        finished = datetime.now(timezone.utc)
        return ExecutionResult(
            status="success" if proc.returncode == 0 else "failed",
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=(finished - started).total_seconds(),
            metadata={"args": args, "timeout": timeout_seconds},
        )
    except subprocess.TimeoutExpired as exc:
        finished = datetime.now(timezone.utc)
        return ExecutionResult(
            status="timeout",
            exit_code=None,
            stdout=exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=(finished - started).total_seconds(),
            metadata={"args": args, "timeout": timeout_seconds},
        )
