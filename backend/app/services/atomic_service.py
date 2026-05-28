from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from app.repositories.atomic_repository import (
    create_failed_import_run,
    get_catalog_summary,
    list_techniques,
    list_tests,
    replace_catalog,
)

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

        for test in atomic_tests:
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
