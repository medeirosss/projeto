from __future__ import annotations

import os
import sys
from pathlib import Path

# This file must IMPORT the service class instead of executing the service
# module with `python -m`. Pywin32 stores the class import path during install.
# If installed through `python -m magi_runner.service.windows_service`, the class
# may be registered as `__main__.MagiRunnerWindowsService`, which pythonservice.exe
# cannot import when SCM starts the service.

BASE_DIR = Path(__file__).resolve().parents[1]
os.environ.setdefault("MAGI_RUNNER_HOME", str(BASE_DIR))
os.environ.setdefault("MAGI_RUNNER_CONFIG", str(BASE_DIR / "settings.json"))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import win32serviceutil  # type: ignore
from magi_runner.service.windows_service import MagiRunnerWindowsService

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MagiRunnerWindowsService)
