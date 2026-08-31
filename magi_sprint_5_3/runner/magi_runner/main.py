from __future__ import annotations

import argparse
import json
import shutil
import time
import requests
from pathlib import Path
from typing import Any


from magi_runner.api.client import MagiApiClient
from magi_runner.api.offline import OfflineJobSource
from magi_runner.core.config import load_config, update_config_values, persist_runner_credentials
from magi_runner.core.logging import setup_logging
from magi_runner.core.scheduler import JobScheduler
from magi_runner.core.watchdog import Watchdog
from magi_runner.core.state import LocalState
from magi_runner.core.update import UpdateManager
from magi_runner.core.version import __version__
from magi_runner.core.doctor import print_doctor
from magi_runner.core.security import security_report
from magi_runner.services.heartbeat import HeartbeatThread
from magi_runner.utils.platform_info import get_host_info


def ensure_settings(path: Path) -> None:
    if path.exists():
        return
    example = Path("settings.example.json")
    if example.exists():
        shutil.copy2(example, path)
        raise SystemExit(f"Created {path}. Edit it and run again.")
    raise SystemExit(f"Missing settings file: {path}")


def _stop_requested(stop_event: Any | None) -> bool:
    if stop_event is None:
        return False
    try:
        # pywin32 event objects return WAIT_OBJECT_0 when signaled.
        import win32event  # type: ignore

        return win32event.WaitForSingleObject(stop_event, 0) == win32event.WAIT_OBJECT_0
    except Exception:
        return bool(getattr(stop_event, "is_set", lambda: False)())



def _flush_result_spool(api: MagiApiClient, state: LocalState, logger) -> None:
    """Retry results that were executed but not acknowledged by the backend."""
    for item in state.list_spooled_results():
        job_id = str(item.get("job_id") or "")
        result = item.get("result")
        if not job_id or not isinstance(result, dict):
            if job_id:
                state.remove_spooled_result(job_id)
            continue
        try:
            ack = api.send_result(job_id, result)
            state.remove_spooled_result(job_id)
            state.mark_completed(job_id)
            if ack.get("discard_result"):
                logger.info(
                    "Discarded stale spooled result for job %s after backend terminal acknowledgement: %s (%s)",
                    job_id,
                    ack.get("reason") or "terminal",
                    ack.get("job_status") or "unknown",
                )
            else:
                logger.info("Previously spooled result delivered for job %s", job_id)
        except Exception as exc:
            logger.warning("Result delivery retry still pending for job %s: %s", job_id, exc)


def run_runner(config_path: Path, once: bool = False, stop_event: Any | None = None) -> None:
    ensure_settings(config_path)
    config = load_config(config_path)
    logger = setup_logging(config.data_path, config.log_level)
    state = LocalState(config.data_path)
    scheduler = JobScheduler(config, state, logger)
    watchdog = Watchdog(config.data_path, logger, interval_seconds=config.heartbeat_interval_seconds)
    watchdog.start()

    logger.info("Starting Magi Runner v2 %s | offline_mode=%s | data_dir=%s", __version__, config.offline_mode, config.data_path)
    updater = UpdateManager(config, logger)
    last_update_check = 0.0

    try:
        if config.offline_mode:
            source = OfflineJobSource(config.offline_jobs_file, state)
            while not _stop_requested(stop_event):
                watchdog.beat()
                if config.update_enabled and config.update_auto_apply and time.time() - last_update_check >= config.update_check_interval_seconds:
                    last_update_check = time.time()
                    try:
                        update_result = updater.apply()
                        logger.info("Update check result: %s", update_result.get("status"))
                        if update_result.get("restart_required"):
                            logger.info("Update applied. Restart required; exiting runner loop.")
                            break
                    except Exception as exc:
                        logger.exception("Auto update failed: %s", exc)
                job = source.get_job()
                if not job:
                    logger.info("No offline jobs available")
                    if once:
                        break
                    time.sleep(config.poll_interval_seconds)
                    continue
                result = scheduler.run_job(job)
                state.mark_completed(str(job.get("job_id") or job.get("id")))
                print(json.dumps(result, indent=2, ensure_ascii=False))
                if once:
                    break
                time.sleep(config.poll_interval_seconds)
            return

        api = MagiApiClient(config, logger)

        # In service mode the Magi backend may still be offline, unreachable,
        # or not yet patched with the Runner API. The Windows service must stay
        # alive and retry registration instead of exiting immediately.
        while (not config.runner_id or not config.runner_secret) and not _stop_requested(stop_event):
            try:
                logger.info("Registering runner on Magi backend: %s", config.server_url)
                registration = api.register(get_host_info())
                if registration.get("runner_id") and registration.get("runner_secret"):
                    persist_runner_credentials(config_path, registration["runner_id"], registration["runner_secret"])
                    config.runner_id = registration["runner_id"]
                    config.runner_secret = registration["runner_secret"]
                    logger.info("Runner credentials saved to %s", config_path)
                logger.info("Runner registered: %s", registration.get("runner_id"))
                break
            except Exception as exc:
                logger.warning(
                    "Runner registration failed; will retry in %s seconds. error=%s",
                    config.poll_interval_seconds,
                    exc,
                )
                if once:
                    raise
                time.sleep(config.poll_interval_seconds)

        if _stop_requested(stop_event):
            logger.info("Stop requested before online loop started")
            return

        heartbeat = HeartbeatThread(api, config.heartbeat_interval_seconds, lambda: scheduler.active_jobs, logger)
        heartbeat.start()
        try:
            while not _stop_requested(stop_event):
                watchdog.beat()
                try:
                    if config.update_enabled and config.update_auto_apply and time.time() - last_update_check >= config.update_check_interval_seconds:
                        last_update_check = time.time()
                        update_result = updater.apply()
                        logger.info("Update check result: %s", update_result.get("status"))
                        if update_result.get("restart_required"):
                            logger.info("Update applied. Restart required; exiting runner loop.")
                            break
                    _flush_result_spool(api, state, logger)
                    job = api.get_job()
                    if job:
                        job_id = str(job.get("job_id") or job.get("id"))
                        result = scheduler.run_job(job)
                        try:
                            ack = api.send_result(job_id, result)
                            state.remove_spooled_result(job_id)
                            state.mark_completed(job_id)
                            if ack.get("discard_result"):
                                logger.info(
                                    "Backend marked job %s terminal; local result discarded (%s/%s)",
                                    job_id,
                                    ack.get("reason") or "terminal",
                                    ack.get("job_status") or "unknown",
                                )
                        except Exception as exc:
                            state.spool_result(job_id, result)
                            logger.warning(
                                "Result for job %s was executed but not acknowledged; "
                                "saved to durable retry spool. error=%s",
                                job_id,
                                exc,
                            )
                except requests.RequestException as exc:
                    logger.warning("Backend connection lost during polling: %s", exc)
                    try:
                        api.reset_session()
                    except Exception:
                        pass
                    if once:
                        raise
                    retry_seconds = max(2, min(30, int(config.poll_interval_seconds)))
                    logger.info("Retrying backend connection in %s seconds...", retry_seconds)
                    time.sleep(retry_seconds)
                    continue
                except Exception as exc:
                    logger.exception("Runner loop iteration failed: %s", exc)
                if once:
                    break
                time.sleep(config.poll_interval_seconds)
        finally:
            heartbeat.stop()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    finally:
        watchdog.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Magi Runner v2")
    parser.add_argument("--config", default="settings.json", help="Path to settings.json")
    parser.add_argument("--once", action="store_true", help="Run one job and exit")
    parser.add_argument("--version", action="store_true", help="Print runner version and exit")
    parser.add_argument("--check-update", action="store_true", help="Check update manifest and exit")
    parser.add_argument("--apply-update", action="store_true", help="Apply available update and exit")
    parser.add_argument("--rollback-update", action="store_true", help="Rollback to the last local backup and exit")
    parser.add_argument("--doctor", action="store_true", help="Run local pre-flight checks and exit")
    parser.add_argument("--security-report", action="store_true", help="Print redacted configuration hardening report and exit")
    parser.add_argument("--set-server-url", help="Set Magi backend URL in settings.json, e.g. http://192.168.1.10:8000")
    parser.add_argument("--set-registration-token", help="Set Runner registration token in settings.json")
    parser.add_argument("--online", action="store_true", help="Set offline_mode=false in settings.json")
    parser.add_argument("--offline", action="store_true", help="Set offline_mode=true in settings.json")
    args = parser.parse_args()
    if args.set_server_url or args.set_registration_token or args.online or args.offline:
        updates = {}
        if args.set_server_url:
            updates["server_url"] = args.set_server_url.rstrip("/")
        if args.set_registration_token:
            updates["registration_token"] = args.set_registration_token
        if args.online:
            updates["offline_mode"] = False
        if args.offline:
            updates["offline_mode"] = True
        updated = update_config_values(Path(args.config), **updates)
        print(json.dumps({"updated": True, "config": {k: ("***" if "token" in k or "secret" in k else v) for k, v in updated.items()}}, indent=2, ensure_ascii=False))
        return
    if args.version:
        print(__version__)
        return
    if args.doctor:
        print_doctor(Path(args.config))
        return
    if args.security_report:
        print(json.dumps(security_report(Path(args.config)), indent=2, ensure_ascii=False))
        return
    if args.check_update or args.apply_update or args.rollback_update:
        ensure_settings(Path(args.config))
        config = load_config(Path(args.config))
        logger = setup_logging(config.data_path, config.log_level)
        updater = UpdateManager(config, logger)
        if args.rollback_update:
            print(json.dumps(updater.rollback(), indent=2, ensure_ascii=False))
        elif args.apply_update:
            print(json.dumps(updater.apply(), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(updater.check().as_dict(), indent=2, ensure_ascii=False))
        return
    run_runner(config_path=Path(args.config), once=args.once)
