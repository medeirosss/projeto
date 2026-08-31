from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager
except ImportError as exc:  # pragma: no cover - Windows only
    raise SystemExit("pywin32 is required to install/run the Windows Service. Run: pip install pywin32") from exc


def _resolve_base_dir() -> Path:
    env_home = os.environ.get("MAGI_RUNNER_HOME")
    if env_home:
        return Path(env_home).resolve()
    # .../magi_runner/service/windows_service.py -> package root parent
    return Path(__file__).resolve().parents[2]


def _append_boot_log(base_dir: Path, message: str) -> None:
    try:
        log_dir = base_dir / "runner_data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        with (log_dir / "service_boot.log").open("a", encoding="utf-8") as fh:
            ts = datetime.now(timezone.utc).isoformat()
            fh.write(f"{ts} | {message}\n")
    except Exception:
        # Never let diagnostic logging kill service startup.
        pass


class MagiRunnerWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = "MagiRunnerV2"
    _svc_display_name_ = "Magi Runner v2"
    _svc_description_ = "Magi Runner v2 service for executing jobs and collecting evidences."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        try:
            base_dir = _resolve_base_dir()
            _append_boot_log(base_dir, f"service object initialized | argv={sys.argv} | executable={sys.executable}")
        except Exception:
            pass

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        base_dir = _resolve_base_dir()
        config_path = Path(os.environ.get("MAGI_RUNNER_CONFIG", base_dir / "settings.json")).resolve()
        try:
            os.chdir(str(base_dir))
            if str(base_dir) not in sys.path:
                sys.path.insert(0, str(base_dir))
            _append_boot_log(base_dir, f"SvcDoRun entered | base_dir={base_dir} | config={config_path} | python={sys.executable} | sys_path_0={sys.path[0] if sys.path else ''}")
            servicemanager.LogInfoMsg("Magi Runner v2 service starting")
            # Signal SCM as early as possible. Imports and backend registration happen after this.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            try:
                from magi_runner.main import run_runner
                _append_boot_log(base_dir, "imported magi_runner.main successfully")
            except Exception as import_exc:
                _append_boot_log(base_dir, f"failed to import magi_runner.main: {import_exc}\n{traceback.format_exc()}")
                raise
            run_runner(config_path=config_path, once=False, stop_event=self.stop_event)
        except Exception as exc:
            tb = traceback.format_exc()
            _append_boot_log(base_dir, f"service stopped with error: {exc}\n{tb}")
            servicemanager.LogErrorMsg(f"Magi Runner v2 service stopped with error: {exc}")
            raise
        finally:
            _append_boot_log(base_dir, "service stopped")
            servicemanager.LogInfoMsg("Magi Runner v2 service stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MagiRunnerWindowsService)
