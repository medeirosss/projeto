"""Runner de referência para Magi Atomic Red Team - Etapa 3B.

Modo padrão: dry-run.
Ele valida o fluxo Magi -> Runner -> Resultado sem executar testes reais.

Variáveis:
  MAGI_API_URL=http://localhost:8000
  MAGI_RUNNER_ID=runner-lab-01
  MAGI_RUNNER_NAME=Atomic Lab Runner
  MAGI_RUNNER_POLL_SECONDS=5
  MAGI_ATOMIC_RUNNER_MODE=dry_run
"""
from __future__ import annotations

import os
import socket
import time
from typing import Any

import requests

MAGI_API_URL = os.getenv("MAGI_API_URL", "http://localhost:8000").rstrip("/")
RUNNER_ID = os.getenv("MAGI_RUNNER_ID", "runner-lab-01")
RUNNER_NAME = os.getenv("MAGI_RUNNER_NAME", "Atomic Lab Runner")
POLL_SECONDS = int(os.getenv("MAGI_RUNNER_POLL_SECONDS", "5"))
RUNNER_MODE = os.getenv("MAGI_ATOMIC_RUNNER_MODE", "dry_run").lower()


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
    })


def heartbeat() -> None:
    post("/api/runner/heartbeat", {"runner_id": RUNNER_ID})


def finish_job(job_id: int, status: str, result: dict[str, Any], error: str | None = None) -> None:
    post(f"/api/runner/jobs/{job_id}/result", {
        "runner_id": RUNNER_ID,
        "status": status,
        "result": result,
        "error": error,
    })


def handle_atomic_validation(job: dict[str, Any]) -> None:
    payload = job.get("payload") or {}
    command_preview = payload.get("command_preview") or ""

    # Segurança: por padrão, esta referência não executa o Atomic.
    # Ela apenas confirma que o job chegou ao Runner e retorna evidência operacional.
    if RUNNER_MODE != "execute_preview":
        finish_job(job["id"], "success", {
            "mode": "dry_run",
            "exit_code": 0,
            "stdout": (
                "DRY-RUN OK. Job recebido pelo Runner.\n"
                f"Technique: {payload.get('technique_id')}\n"
                f"Test number: {payload.get('atomic_test_number')}\n"
                f"Command preview: {command_preview}\n"
            ),
            "stderr": "",
        })
        return

    # Modo execute_preview reservado para laboratório. Mesmo aqui a referência
    # deve executar apenas comandos de preview/detalhes, nunca teste real.
    # Implementação real deve ser feita com allowlist local e controle de identidade.
    finish_job(job["id"], "success", {
        "mode": "execute_preview_placeholder",
        "exit_code": 0,
        "stdout": "Preview execution placeholder. Implementar allowlist local antes de executar PowerShell.",
        "stderr": "",
    })


def poll_once() -> None:
    jobs = get(f"/api/runner/jobs?runner_id={RUNNER_ID}").get("jobs", [])
    for job in jobs:
        if job.get("job_type") == "atomic_validation":
            handle_atomic_validation(job)
        else:
            finish_job(job["id"], "failed", {"exit_code": 1, "stdout": "", "stderr": "Job type não suportado por este runner."})


def main() -> None:
    print(f"Magi Atomic Runner iniciado: {RUNNER_ID} -> {MAGI_API_URL} | mode={RUNNER_MODE}")
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
