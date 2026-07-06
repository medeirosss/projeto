"""Runner de referência para Magi Atomic Red Team - Etapa 3C.

Objetivo:
  Validar o fluxo Magi -> Runner -> PowerShell Atomic preview -> Resultado -> Magi.

Segurança:
  - O modo padrão continua sendo dry_run, sem executar PowerShell.
  - O modo execute_preview executa apenas ShowDetailsBrief ou CheckPrereqs.
  - Este runner NÃO executa o Atomic real sem alteração explícita futura.

Variáveis:
  MAGI_API_URL=http://localhost:8000
  MAGI_RUNNER_ID=runner-lab-01
  MAGI_RUNNER_NAME=Atomic Lab Runner
  MAGI_RUNNER_POLL_SECONDS=5
  MAGI_ATOMIC_RUNNER_MODE=dry_run            # dry_run | execute_preview | execute_lab
  MAGI_ATOMIC_PREVIEW_ACTION=show_details    # show_details | check_prereqs
  MAGI_ATOMICS_FOLDER=C:\Program Files\Magi Runner\atomic-red-team\atomics
  MAGI_POWERSHELL_EXE=powershell             # powershell | pwsh
"""
from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import time
from typing import Any

import requests

MAGI_API_URL = os.getenv("MAGI_API_URL", "http://localhost:8000").rstrip("/")
RUNNER_ID = os.getenv("MAGI_RUNNER_ID", "runner-lab-01")
RUNNER_NAME = os.getenv("MAGI_RUNNER_NAME", "Atomic Lab Runner")
POLL_SECONDS = int(os.getenv("MAGI_RUNNER_POLL_SECONDS", "5"))
RUNNER_MODE = os.getenv("MAGI_ATOMIC_RUNNER_MODE", "dry_run").lower()
PREVIEW_ACTION = os.getenv("MAGI_ATOMIC_PREVIEW_ACTION", "show_details").lower()
POWERSHELL_EXE = os.getenv("MAGI_POWERSHELL_EXE", "powershell")
ATOMICS_FOLDER = os.getenv("MAGI_ATOMICS_FOLDER", r"C:\Program Files\Magi Runner\atomic-red-team\atomics")
RUNNER_VERSION = "validation-engine-final-20260706"

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def local_ip() -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return None


def runner_metadata() -> dict[str, Any]:
    return {
        "ip_address": local_ip(),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "runner_version": RUNNER_VERSION,
        "atomic_mode": RUNNER_MODE,
        "preview_action": PREVIEW_ACTION,
    }


def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    res = requests.post(f"{MAGI_API_URL}{path}", json=payload, timeout=30)
    res.raise_for_status()
    return res.json()


def get(path: str) -> dict[str, Any]:
    res = requests.get(f"{MAGI_API_URL}{path}", timeout=30)
    res.raise_for_status()
    return res.json()


def register() -> None:
    post("/api/runner/register", {
        "runner_id": RUNNER_ID,
        "name": RUNNER_NAME,
        "hostname": socket.gethostname(),
        "metadata": runner_metadata(),
    })


def heartbeat() -> None:
    post("/api/runner/heartbeat", {
        "runner_id": RUNNER_ID,
        "metadata": runner_metadata(),
    })


def finish_job(job_id: int, status: str, result: dict[str, Any], error: str | None = None) -> None:
    post(f"/api/runner/jobs/{job_id}/result", {
        "runner_id": RUNNER_ID,
        "status": status,
        "result": result,
        "error": error,
    })


def build_atomic_preview_command(payload: dict[str, Any]) -> str:
    technique_id = str(payload.get("technique_id") or "").strip()
    test_number = int(payload.get("atomic_test_number") or 1)

    if not TECHNIQUE_RE.match(technique_id):
        raise ValueError(f"Invalid MITRE technique id: {technique_id}")
    if test_number < 1 or test_number > 999:
        raise ValueError(f"Invalid Atomic test number: {test_number}")

    if PREVIEW_ACTION == "check_prereqs":
        return f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -CheckPrereqs"

    return f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -ShowDetailsBrief"



def build_atomic_execute_lab_command(payload: dict[str, Any]) -> str:
    technique_id = str(payload.get("technique_id") or "").strip()
    test_number = int(payload.get("atomic_test_number") or 0)

    if not TECHNIQUE_RE.match(technique_id):
        raise ValueError(f"Invalid MITRE technique id: {technique_id}")
    if test_number < 1 or test_number > 999:
        raise ValueError(f"Invalid Atomic test number: {test_number}")
    if payload.get("allow_real_execution") is not True:
        raise ValueError("Real Atomic LAB execution was not explicitly allowed by backend payload.")

    return (
        f'Invoke-AtomicTest {technique_id} '
        f'-TestNumbers {test_number} '
        f'-PathToAtomicsFolder "{ATOMICS_FOLDER}"'
    )

def run_powershell(command: str) -> dict[str, Any]:
    wrapped = (
        "$ErrorActionPreference = 'Continue'; "
        "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop; "
        f"{command}"
    )
    completed = subprocess.run(
        [POWERSHELL_EXE, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
        "command": command,
        "powershell": POWERSHELL_EXE,
        "executed_real_test": False,
    }


def handle_atomic_validation(job: dict[str, Any]) -> None:
    payload = job.get("payload") or {}
    command_preview = payload.get("command_preview") or ""

    job_mode = str(payload.get("mode") or "").lower()

    if RUNNER_MODE == "execute_lab" and job_mode == "execute_lab":
        try:
            safe_command = build_atomic_execute_lab_command(payload)
            result = run_powershell(safe_command)
            result.update({
                "mode": "execute_lab",
                "executed_real_test": True,
                "allow_real_execution": True,
                "runner_version": RUNNER_VERSION,
                "metadata": runner_metadata(),
            })
            finish_job(job["id"], "success" if result["exit_code"] == 0 else "failed", result)
            return
        except subprocess.TimeoutExpired as exc:
            finish_job(job["id"], "timeout", {
                "mode": "execute_lab",
                "executed_real_test": True,
                "exit_code": 124,
                "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
                "stderr": "Timeout ao executar Atomic LAB.",
                "runner_version": RUNNER_VERSION,
                "metadata": runner_metadata(),
            }, error="Timeout ao executar Atomic LAB.")
            return
        except Exception as exc:
            finish_job(job["id"], "error", {
                "mode": "execute_lab",
                "runner_version": RUNNER_VERSION,
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
                "metadata": runner_metadata(),
            }, error=str(exc))
            return

    if RUNNER_MODE != "execute_preview":
        finish_job(job["id"], "success", {
            "mode": "dry_run",
            "runner_version": RUNNER_VERSION,
            "exit_code": 0,
            "stdout": (
                "DRY-RUN OK. Job recebido pelo Runner. Nenhum comando foi executado.\n"
                f"Runner: {RUNNER_ID}\n"
                f"Technique: {payload.get('technique_id')}\n"
                f"Test number: {payload.get('atomic_test_number')}\n"
                f"Command preview: {command_preview}\n"
            ),
            "stderr": "",
            "metadata": runner_metadata(),
        })
        return

    try:
        safe_command = build_atomic_preview_command(payload)
        result = run_powershell(safe_command)
        result.update({
            "mode": "execute_preview",
            "preview_action": PREVIEW_ACTION,
            "runner_version": RUNNER_VERSION,
            "metadata": runner_metadata(),
        })
        finish_job(job["id"], "success" if result["exit_code"] == 0 else "failed", result)
    except subprocess.TimeoutExpired as exc:
        finish_job(job["id"], "timeout", {
            "mode": "execute_preview",
            "runner_version": RUNNER_VERSION,
            "exit_code": 124,
            "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
            "stderr": "Timeout ao executar preview Atomic.",
            "metadata": runner_metadata(),
        }, error="Timeout ao executar preview Atomic.")
    except Exception as exc:
        finish_job(job["id"], "error", {
            "mode": "execute_preview",
            "runner_version": RUNNER_VERSION,
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "metadata": runner_metadata(),
        }, error=str(exc))


def poll_once() -> None:
    jobs = get(f"/api/runner/jobs?runner_id={RUNNER_ID}").get("jobs", [])
    for job in jobs:
        if job.get("job_type") == "atomic_validation":
            handle_atomic_validation(job)
        else:
            finish_job(job["id"], "failed", {"exit_code": 1, "stdout": "", "stderr": "Job type não suportado por este runner."})


def main() -> None:
    print(f"Magi Atomic Runner iniciado: {RUNNER_ID} -> {MAGI_API_URL} | mode={RUNNER_MODE} | preview={PREVIEW_ACTION}")
    register()
    while True:
        try:
            heartbeat()
            poll_once()
        except Exception as exc:
            print(f"Erro no loop do runner: {exc}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
