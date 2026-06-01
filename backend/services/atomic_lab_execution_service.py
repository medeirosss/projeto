from __future__ import annotations

import json
from datetime import datetime
from sqlalchemy import text

from app.database.connection import SessionLocal
from app.repositories.runner_repository import create_runner_job


def build_atomic_command_preview(technique_id: str, atomic_test_number: int) -> str:
    return (
        f'Invoke-AtomicTest {technique_id} '
        f'-TestNumbers {int(atomic_test_number)} '
        f'-PathToAtomicsFolder "C:\\Program Files\\Magi Runner\\atomic-red-team\\atomics"'
    )


def create_atomic_lab_execution_service(atomic_test_id: int, runner_id: str, current_user: dict | None = None):
    current_user = current_user or {"username": "ui", "role": "admin"}

    if current_user.get("role") != "admin":
        raise ValueError("Somente usuários admin podem executar Atomic LAB.")

    if not runner_id:
        raise ValueError("runner_id is required")

    with SessionLocal() as db:
        test = db.execute(
            text("""
                SELECT
                    id, technique_id, atomic_test_number, atomic_name,
                    executor_name, risk_level, approved_for_lab,
                    approved_for_execution, requires_reboot,
                    executor_elevation_required, has_dependencies,
                    dependency_count, enabled
                FROM atomic_tests
                WHERE id = :atomic_test_id
            """),
            {"atomic_test_id": atomic_test_id},
        ).mappings().first()

        if not test:
            raise ValueError("Atomic test not found")

        blockers = []
        if not bool(test["enabled"]):
            blockers.append("Teste desabilitado no catálogo.")
        if not bool(test["approved_for_execution"]):
            blockers.append("Teste não aprovado para execução.")
        if not bool(test["approved_for_lab"]):
            blockers.append("Teste não aprovado para LAB.")

        if blockers:
            return {
                "success": False,
                "blocked": True,
                "blockers": blockers,
                "atomic_test_id": atomic_test_id,
            }

        technique_id = test["technique_id"]
        atomic_test_number = int(test["atomic_test_number"] or 1)
        command_preview = build_atomic_command_preview(technique_id, atomic_test_number)

        payload = {
            "mode": "execute_lab",
            "risk_level": str(test["risk_level"] or "").lower(),
            "atomic_name": test["atomic_name"],
            "executor_name": test["executor_name"],
            "technique_id": technique_id,
            "atomic_test_number": atomic_test_number,
            "atomic_test_id": atomic_test_id,
            "approved_for_execution": True,
            "approved_for_lab": True,
            "allow_real_execution": True,
            "requires_reboot": bool(test["requires_reboot"]),
            "requires_admin": bool(test["executor_elevation_required"]),
            "has_dependencies": bool(test["has_dependencies"]),
            "dependency_count": int(test["dependency_count"] or 0),
            "approved_by": current_user.get("username", "ui"),
            "approved_at": datetime.utcnow().isoformat(),
            "command_preview": command_preview,
            "validation_type": "atomic_red_team",
        }

        execution = db.execute(
            text("""
                INSERT INTO atomic_execution_jobs (
                    atomic_test_id, technique_id, atomic_test_number,
                    runner_id, target_host, status, requested_by,
                    approved_by, command_preview, payload, created_at
                )
                VALUES (
                    :atomic_test_id, :technique_id, :atomic_test_number,
                    :runner_id, NULL, 'queued', :requested_by,
                    :approved_by, :command_preview, CAST(:payload AS JSONB),
                    :created_at
                )
                RETURNING *
            """),
            {
                "atomic_test_id": atomic_test_id,
                "technique_id": technique_id,
                "atomic_test_number": atomic_test_number,
                "runner_id": runner_id,
                "requested_by": current_user.get("username", "ui"),
                "approved_by": current_user.get("username", "ui"),
                "command_preview": command_preview,
                "payload": json.dumps(payload),
                "created_at": datetime.utcnow(),
            },
        ).mappings().first()
        db.commit()

    payload["atomic_execution_id"] = execution["id"]

    runner_job = create_runner_job(
        runner_id=runner_id,
        job_type="atomic_validation",
        target=None,
        payload=payload,
    )

    with SessionLocal() as db:
        db.execute(
            text("UPDATE atomic_execution_jobs SET runner_job_id = :runner_job_id WHERE id = :execution_id"),
            {"runner_job_id": runner_job["id"], "execution_id": execution["id"]},
        )
        db.commit()

    return {
        "success": True,
        "blocked": False,
        "execution_id": execution["id"],
        "runner_job": runner_job,
        "command_preview": command_preview,
        "warnings": {
            "risk_level": payload["risk_level"],
            "requires_reboot": payload["requires_reboot"],
            "requires_admin": payload["requires_admin"],
            "has_dependencies": payload["has_dependencies"],
            "dependency_count": payload["dependency_count"],
        },
    }
