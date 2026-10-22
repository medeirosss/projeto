from __future__ import annotations

import sys
from pathlib import Path

from .base import ExecutionResult
from .process import run_subprocess


class PythonExecutor:
    name = "python"

    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        code = job.get("code") or job.get("payload", {}).get("code")
        script = job.get("script") or job.get("payload", {}).get("script")
        if code:
            script_path = Path(workdir) / "job_script.py"
            script_path.write_text(code, encoding="utf-8")
            return run_subprocess([sys.executable, str(script_path)], workdir, timeout_seconds)
        if script:
            return run_subprocess([sys.executable, script], workdir, timeout_seconds)
        raise ValueError("Python job requires 'code' or 'script'")
