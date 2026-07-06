from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.repositories.atomic_repository import (
    dispatch_atomic_execution_job,
    get_atomic_execution_by_id,
    approve_atomic_test,
    create_atomic_execution_preview,
    create_failed_import_run,
    get_catalog_summary,
    get_atomic_test_by_id,
    list_atomic_executions,
    list_techniques,
    list_tests,
    replace_catalog,
    update_atomic_test_flags,
    update_atomic_test_risk,
    mark_atomic_execution_blocked,
)
from app.repositories.runner_repository import create_runner_job

SENSITIVE_KEYWORDS = (
    "credential", "password", "hash", "lsass", "mimikatz", "dump", "exfil", "ransom",
    "persistence", "registry run key", "scheduled task", "disable", "delete", "destructive",
    "lateral", "remote services", "keylog", "token", "kerberoast", "dcsync",
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _risk_for_test(test: dict[str, Any]) -> tuple[str, list[str]]:
    text = " ".join([
        str(test.get("name") or ""),
        str(test.get("description") or ""),
        str(test.get("executor", {}).get("command") or ""),
        str(test.get("executor", {}).get("cleanup_command") or ""),
    ]).lower()
    flags = [kw for kw in SENSITIVE_KEYWORDS if kw in text]
    elevation = bool(test.get("executor", {}).get("elevation_required"))
    has_dependencies = bool(test.get("dependencies"))
    if any(x in flags for x in ["credential", "password", "hash", "lsass", "mimikatz", "exfil", "ransom", "dcsync", "kerberoast"]):
        return "high", flags
    if elevation or has_dependencies or flags:
        return "medium", flags
    return "low", flags


def parse_atomic_catalog(atomics_path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    root = Path(atomics_path).expanduser().resolve()
    if root.name != "atomics" and (root / "atomics").exists():
        root = root / "atomics"
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Diretório atomics não encontrado: {root}")

    techniques: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    skipped = 0

    for yaml_file in sorted(root.glob("T*/T*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
        except Exception:
            skipped += 1
            continue

        technique_id = str(data.get("attack_technique") or yaml_file.parent.name).strip()
        display_name = str(data.get("display_name") or technique_id).strip()
        atomic_tests = _as_list(data.get("atomic_tests"))

        platforms: set[str] = set()
        executors: set[str] = set()
        technique_tests = 0

        for test_index, test in enumerate(atomic_tests, start=1):
            if not isinstance(test, dict):
                skipped += 1
                continue
            executor = test.get("executor") or {}
            executor_name = executor.get("name") if isinstance(executor, dict) else None
            supported_platforms = [str(x) for x in _as_list(test.get("supported_platforms"))]
            for platform in supported_platforms:
                platforms.add(platform)
            if executor_name:
                executors.add(str(executor_name))
            risk_level, risk_flags = _risk_for_test(test)
            dependencies = _as_list(test.get("dependencies"))
            technique_tests += 1
            tests.append({
                "technique_id": technique_id,
                "atomic_test_number": test_index,
                "atomic_name": test.get("name") or "Unnamed atomic test",
                "description": test.get("description"),
                "supported_platforms": supported_platforms,
                "executor_name": executor_name,
                "executor_elevation_required": bool(executor.get("elevation_required")) if isinstance(executor, dict) else False,
                "has_dependencies": bool(dependencies),
                "dependency_count": len(dependencies),
                "input_arguments": test.get("input_arguments") or {},
                "risk_flags": risk_flags,
                "risk_level": risk_level,
                "source_file": str(yaml_file.relative_to(root.parent)),
                "raw_yaml": test,
            })

        techniques.append({
            "technique_id": technique_id,
            "display_name": display_name,
            "attack_tactic": data.get("attack_tactic"),
            "atomic_tests_count": technique_tests,
            "platforms": sorted(platforms),
            "executors": sorted(executors),
            "source_file": str(yaml_file.relative_to(root.parent)),
        })

    return techniques, tests, skipped


def import_atomic_catalog(source_path: str | None = None) -> dict[str, Any]:
    selected_path = source_path or os.getenv("ATOMIC_RED_TEAM_PATH") or "/opt/atomic-red-team/atomics"
    try:
        techniques, tests, skipped = parse_atomic_catalog(selected_path)
        result = replace_catalog(techniques, tests, selected_path, skipped_count=skipped)
        return {"success": True, "import": result}
    except Exception as exc:
        failed = create_failed_import_run(selected_path, str(exc))
        return {"success": False, "import": failed, "detail": str(exc)}


def get_atomic_summary() -> dict[str, Any]:
    return get_catalog_summary()


def get_atomic_techniques(search: str | None = None, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    return {"techniques": list_techniques(search=search, limit=limit, offset=offset)}


def get_atomic_tests(technique_id: str | None = None, platform: str | None = None, executor: str | None = None, risk_level: str | None = None, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    return {"tests": list_tests(technique_id=technique_id, platform=platform, executor=executor, risk_level=risk_level, limit=limit, offset=offset)}


def set_atomic_test_approval(test_id: int, approved: bool = True, approved_by: str | None = None) -> dict[str, Any]:
    return {"success": True, "test": approve_atomic_test(test_id, approved, approved_by=approved_by)}


def set_atomic_test_risk(test_id: int, risk_level: str) -> dict[str, Any]:
    risk = (risk_level or "").strip().lower()
    if risk not in ["low", "medium", "high", "critical"]:
        raise ValueError("risk_level must be low, medium, high or critical")
    return {"success": True, "test": update_atomic_test_risk(test_id, risk)}


def set_atomic_test_flags(test_id: int, flags: dict[str, Any]) -> dict[str, Any]:
    allowed_runner_groups = flags.get("allowed_runner_groups")
    if allowed_runner_groups is not None and not isinstance(allowed_runner_groups, list):
        allowed_runner_groups = [str(allowed_runner_groups)]
    return {
        "success": True,
        "test": update_atomic_test_flags(
            test_id=test_id,
            safe_for_production=bool(flags.get("safe_for_production", False)),
            requires_reboot=bool(flags.get("requires_reboot", False)),
            allowed_runner_groups=allowed_runner_groups or [],
        ),
    }


def _atomic_test_number_or_raise(test: dict[str, Any]) -> int:
    """Retorna o número real do teste no YAML.

    Importante: esse valor não é o id interno do banco.
    Exemplo: T1087.001-8 => atomic_test_number = 8.
    """
    test_number = test.get("atomic_test_number") or test.get("computed_test_number")
    if not test_number:
        raise ValueError("atomic_test_number ausente. Reimporte o catálogo Atomic a partir dos YAMLs.")
    return int(test_number)


def _build_preview_command(test: dict[str, Any]) -> str:
    technique_id = test.get("technique_id")
    test_number = _atomic_test_number_or_raise(test)
    return f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -ShowDetailsBrief"


def _build_execute_lab_command(test: dict[str, Any]) -> str:
    technique_id = test.get("technique_id")
    test_number = _atomic_test_number_or_raise(test)
    return (
        f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} "
        f"-PathToAtomicsFolder \"C:\\Program Files\\Magi Runner\\atomic-red-team\\atomics\""
    )


def _current_user_from_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    payload = payload or {}
    user = payload.get("current_user") or {}
    return {
        "username": user.get("username") or payload.get("requested_by") or payload.get("approved_by") or "ui",
        "role": str(user.get("role") or payload.get("role") or "viewer").lower(),
    }


def prepare_atomic_execution_preview(test_id: int, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    test = get_atomic_test_by_id(test_id)
    if not test:
        raise ValueError("Atomic test not found")

    command_preview = _build_preview_command(test)
    block_reasons: list[str] = []

    if not bool(test.get("approved_for_execution")):
        block_reasons.append("Teste ainda não aprovado para execução.")
    # Regra de produto: o Magi não bloqueia por risco, SO, dependência ou reboot.
    # O único bloqueio real para execução é aprovação/desabilitação pelo admin.

    status = "blocked" if block_reasons else "pending_review"

    execution = create_atomic_execution_preview(
        atomic_test_id=test_id,
        technique_id=test.get("technique_id"),
        atomic_test_number=test.get("atomic_test_number") or test.get("computed_test_number"),
        runner_id=payload.get("runner_id"),
        target_host=payload.get("target_host"),
        requested_by=payload.get("requested_by") or "ui",
        command_preview=command_preview,
        status=status,
        block_reason="; ".join(block_reasons) if block_reasons else None,
        payload={
            "mode": "preview_only",
            "executor_name": test.get("executor_name"),
            "supported_platforms": test.get("supported_platforms") or [],
            "risk_level": test.get("risk_level"),
            "atomic_name": test.get("atomic_name"),
        },
    )

    return {"success": True, "execution": execution, "test": test, "blocked": bool(block_reasons), "block_reasons": block_reasons}




def execute_atomic_lab_test(test_id: int, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cria execução real controlada de Atomic em LAB.

    Esta função NÃO executa localmente no backend. Ela cria um runner_job com
    payload.mode=execute_lab para o Runner executar localmente nele.
    """
    payload = payload or {}
    user = _current_user_from_payload(payload)

    runner_id = payload.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id é obrigatório para execução LAB.")

    test = get_atomic_test_by_id(test_id)
    if not test:
        raise ValueError("Atomic test not found")

    block_reasons: list[str] = []
    if not bool(test.get("enabled")):
        block_reasons.append("Teste desabilitado no catálogo.")
    if not bool(test.get("approved_for_execution")):
        block_reasons.append("Teste não aprovado para execução pelo admin.")
    if not bool(test.get("approved_for_lab")):
        block_reasons.append("Teste não aprovado para LAB pelo admin.")

    # Sem bloqueio de produto por risk_level/requires_reboot/supported_platforms.
    # Esses campos seguem como metadados e evidência para decisão do admin.

    if block_reasons:
        return {"success": False, "blocked": True, "block_reasons": block_reasons, "test": test}

    command_preview = _build_execute_lab_command(test)
    atomic_test_number = _atomic_test_number_or_raise(test)
    now = datetime.utcnow().isoformat()
    runner_payload = {
        "validation_type": "atomic_red_team",
        "mode": "execute_lab",
        "atomic_test_id": test_id,
        "technique_id": test.get("technique_id"),
        "atomic_test_number": int(atomic_test_number),
        "atomic_name": test.get("atomic_name"),
        "executor_name": test.get("executor_name"),
        "risk_level": str(test.get("risk_level") or "low").lower(),
        "command_preview": command_preview,
        "target_host": None,
        "approved_for_execution": True,
        "approved_for_lab": True,
        "allow_real_execution": True,
        "requires_reboot": bool(test.get("requires_reboot")),
        "requires_admin": bool(test.get("executor_elevation_required")),
        "approved_by": user.get("username"),
        "approved_at": now,
    }

    execution = create_atomic_execution_preview(
        atomic_test_id=test_id,
        technique_id=test.get("technique_id"),
        atomic_test_number=int(atomic_test_number),
        runner_id=runner_id,
        target_host=None,
        requested_by=user.get("username"),
        command_preview=command_preview,
        status="queued",
        block_reason=None,
        payload=runner_payload,
    )

    runner_payload["atomic_execution_id"] = execution["id"]
    runner_job = create_runner_job(
        runner_id=runner_id,
        job_type="atomic_validation",
        target=None,
        payload=runner_payload,
    )
    dispatched = dispatch_atomic_execution_job(
        execution_id=int(execution["id"]),
        runner_id=runner_id,
        runner_job_id=int(runner_job["id"]),
        approved_by=user.get("username"),
    )

    return {
        "success": True,
        "blocked": False,
        "execution": dispatched,
        "runner_job": runner_job,
        "command_preview": command_preview,
        "target_note": "Nesta etapa a execução é local no Runner; target/IP ainda não é usado.",
    }


def get_atomic_execution_previews(
    limit: int = 100,
    offset: int = 0,
    search: str | None = None,
    technique_id: str | None = None,
    runner_id: str | None = None,
    status: str | None = None,
    requested_by: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    result = list_atomic_executions(
        limit=limit,
        offset=offset,
        search=search,
        technique_id=technique_id,
        runner_id=runner_id,
        status=status,
        requested_by=requested_by,
        date_from=date_from,
        date_to=date_to,
    )
    return {"executions": result.get("items", []), "total": result.get("total", 0), "limit": limit, "offset": offset}


def get_atomic_execution_detail(execution_id: int) -> dict[str, Any]:
    execution = get_atomic_execution_by_id(execution_id)
    if not execution:
        raise ValueError("Atomic execution job not found")
    return {"success": True, "execution": execution}



def dispatch_atomic_execution_to_runner(execution_id: int, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Libera um preview aprovado para a fila do Runner.

    3B ainda mantém a execução controlada: o backend não executa comando.
    O Runner recebe um job com modo padrão dry_run/show_details.
    """
    payload = payload or {}
    execution = get_atomic_execution_by_id(execution_id)
    if not execution:
        raise ValueError("Atomic execution job not found")

    status = str(execution.get("status") or "")
    if status not in ["pending_review", "prepared"]:
        raise ValueError(f"Execution status must be pending_review/prepared before dispatch. Current status: {status}")

    block_reasons: list[str] = []
    if not bool(execution.get("approved_for_execution")):
        block_reasons.append("Teste não aprovado para execução.")
    # Sem bloqueio de produto por risk_level/requires_reboot; apenas aprovação/admin e runner.

    runner_id = payload.get("runner_id") or execution.get("runner_id")
    if not runner_id:
        block_reasons.append("runner_id é obrigatório para despacho ao Runner.")

    if block_reasons:
        blocked = mark_atomic_execution_blocked(execution_id, "; ".join(block_reasons))
        return {"success": False, "blocked": True, "block_reasons": block_reasons, "execution": blocked}

    runner_payload = {
        "validation_type": "atomic_red_team",
        "atomic_execution_id": execution["id"],
        "atomic_test_id": execution.get("atomic_test_id"),
        "technique_id": execution.get("technique_id"),
        "atomic_test_number": execution.get("atomic_test_number"),
        "atomic_name": execution.get("atomic_name"),
        "executor_name": execution.get("executor_name"),
        "risk_level": execution.get("risk_level"),
        "command_preview": execution.get("command_preview"),
        "mode": payload.get("mode") or "dry_run",
        "target_host": payload.get("target_host") or execution.get("target_host"),
    }

    runner_job = create_runner_job(
        runner_id=runner_id,
        job_type="atomic_validation",
        target=runner_payload.get("target_host"),
        payload=runner_payload,
    )

    dispatched = dispatch_atomic_execution_job(
        execution_id=execution_id,
        runner_id=runner_id,
        runner_job_id=int(runner_job["id"]),
        approved_by=payload.get("approved_by") or payload.get("requested_by") or "ui",
    )

    return {"success": True, "blocked": False, "execution": dispatched, "runner_job": runner_job}
