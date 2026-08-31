from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class ExecutionResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration_seconds: float
    metadata: dict[str, Any]


class Executor(Protocol):
    name: str

    def run(self, job: dict[str, Any], workdir: str, timeout_seconds: int) -> ExecutionResult:
        ...
