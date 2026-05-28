from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.database.connection import SessionLocal


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def replace_catalog(techniques: list[dict[str, Any]], tests: list[dict[str, Any]], source_path: str, skipped_count: int = 0) -> dict[str, Any]:
    now = datetime.utcnow()
    with SessionLocal() as db:
        db.execute(text("DELETE FROM atomic_tests"))
        db.execute(text("DELETE FROM atomic_techniques"))

        for item in techniques:
            db.execute(text("""
                INSERT INTO atomic_techniques (
                    technique_id, display_name, attack_tactic, atomic_tests_count,
                    platforms, executors, source_file, enabled, created_at, updated_at
                ) VALUES (
                    :technique_id, :display_name, :attack_tactic, :atomic_tests_count,
                    CAST(:platforms AS JSONB), CAST(:executors AS JSONB), :source_file, TRUE, :now, :now
                )
            """), {
                "technique_id": item["technique_id"],
                "display_name": item.get("display_name") or item["technique_id"],
                "attack_tactic": item.get("attack_tactic"),
                "atomic_tests_count": item.get("atomic_tests_count") or 0,
                "platforms": _json(item.get("platforms") or []),
                "executors": _json(item.get("executors") or []),
                "source_file": item.get("source_file"),
                "now": now,
            })

        for item in tests:
            db.execute(text("""
                INSERT INTO atomic_tests (
                    technique_id, atomic_test_number, atomic_name, description, supported_platforms,
                    executor_name, executor_elevation_required, has_dependencies,
                    dependency_count, input_arguments, risk_flags, risk_level,
                    approved_for_lab, enabled, source_file, raw_yaml, created_at, updated_at
                ) VALUES (
                    :technique_id, :atomic_name, :description, CAST(:supported_platforms AS JSONB),
                    :executor_name, :executor_elevation_required, :has_dependencies,
                    :dependency_count, CAST(:input_arguments AS JSONB), CAST(:risk_flags AS JSONB), :risk_level,
                    FALSE, TRUE, :source_file, CAST(:raw_yaml AS JSONB), :now, :now
                )
            """), {
                "technique_id": item["technique_id"],
                "atomic_test_number": item.get("atomic_test_number"),
                "atomic_name": item.get("atomic_name") or "Unnamed atomic test",
                "description": item.get("description"),
                "supported_platforms": _json(item.get("supported_platforms") or []),
                "executor_name": item.get("executor_name"),
                "executor_elevation_required": bool(item.get("executor_elevation_required")),
                "has_dependencies": bool(item.get("has_dependencies")),
                "dependency_count": int(item.get("dependency_count") or 0),
                "input_arguments": _json(item.get("input_arguments") or {}),
                "risk_flags": _json(item.get("risk_flags") or []),
                "risk_level": item.get("risk_level") or "medium",
                "source_file": item.get("source_file"),
                "raw_yaml": _json(item.get("raw_yaml") or {}),
                "now": now,
            })

        run = db.execute(text("""
            INSERT INTO atomic_import_runs (source_path, status, techniques_count, tests_count, skipped_count, created_at)
            VALUES (:source_path, 'success', :techniques_count, :tests_count, :skipped_count, :now)
            RETURNING id, source_path, status, techniques_count, tests_count, skipped_count, created_at
        """), {
            "source_path": source_path,
            "techniques_count": len(techniques),
            "tests_count": len(tests),
            "skipped_count": skipped_count,
            "now": now,
        }).mappings().first()
        db.commit()
        return dict(run)


def create_failed_import_run(source_path: str, error: str) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO atomic_import_runs (source_path, status, error, created_at)
            VALUES (:source_path, 'failed', :error, :now)
            RETURNING id, source_path, status, error, created_at
        """), {"source_path": source_path, "error": error[:4000], "now": datetime.utcnow()}).mappings().first()
        db.commit()
        return dict(row)


def get_catalog_summary() -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT
              (SELECT COUNT(*) FROM atomic_techniques) AS techniques_count,
              (SELECT COUNT(*) FROM atomic_tests) AS tests_count,
              (SELECT COUNT(*) FROM atomic_tests WHERE COALESCE(approved_for_execution, approved_for_lab) = TRUE) AS approved_count,
              (SELECT COUNT(*) FROM atomic_tests WHERE executor_elevation_required = TRUE) AS elevated_count,
              (SELECT COUNT(*) FROM atomic_tests WHERE has_dependencies = TRUE) AS dependencies_count
        """)).mappings().first()
        last = db.execute(text("""
            SELECT id, source_path, status, techniques_count, tests_count, skipped_count, error, created_at
            FROM atomic_import_runs
            ORDER BY id DESC
            LIMIT 1
        """)).mappings().first()
        return {"summary": dict(row), "last_import": dict(last) if last else None}


def list_techniques(search: str | None = None, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
    q = "%" + (search or "").strip().lower() + "%"
    with SessionLocal() as db:
        rows = db.execute(text("""
            SELECT technique_id, display_name, attack_tactic, atomic_tests_count, platforms, executors, enabled, updated_at
            FROM atomic_techniques
            WHERE (:search = '' OR lower(technique_id) LIKE :q OR lower(display_name) LIKE :q OR lower(COALESCE(attack_tactic, '')) LIKE :q)
            ORDER BY technique_id ASC
            LIMIT :limit OFFSET :offset
        """), {"search": (search or "").strip(), "q": q, "limit": limit, "offset": offset}).mappings().all()
        return [dict(row) for row in rows]


def list_tests(technique_id: str | None = None, platform: str | None = None, executor: str | None = None, risk_level: str | None = None, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
            SELECT id, technique_id, atomic_test_number, atomic_name, description, supported_platforms, executor_name,
                   executor_elevation_required, has_dependencies, dependency_count, risk_flags,
                   risk_level, approved_for_lab, COALESCE(approved_for_execution, approved_for_lab) AS approved_for_execution,
                   COALESCE(safe_for_production, FALSE) AS safe_for_production,
                   COALESCE(requires_reboot, FALSE) AS requires_reboot,
                   enabled, source_file
            FROM atomic_tests
            WHERE (:technique_id IS NULL OR technique_id = :technique_id)
              AND (:executor IS NULL OR executor_name = :executor)
              AND (:risk_level IS NULL OR risk_level = :risk_level)
              AND (:platform IS NULL OR supported_platforms::text ILIKE :platform_like)
            ORDER BY technique_id ASC, id ASC
            LIMIT :limit OFFSET :offset
        """), {
            "technique_id": technique_id,
            "executor": executor,
            "risk_level": risk_level,
            "platform": platform,
            "platform_like": f"%{platform}%" if platform else None,
            "limit": limit,
            "offset": offset,
        }).mappings().all()
        return [dict(row) for row in rows]



def get_atomic_test_by_id(test_id: int) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT
                t.id,
                t.technique_id,
                COALESCE(
                    t.atomic_test_number,
                    ROW_NUMBER() OVER (PARTITION BY t.technique_id ORDER BY t.id)
                ) AS computed_test_number,
                t.atomic_test_number,
                t.atomic_name,
                t.description,
                t.supported_platforms,
                t.executor_name,
                t.executor_elevation_required,
                t.has_dependencies,
                t.dependency_count,
                t.risk_flags,
                t.risk_level,
                t.approved_for_lab,
                COALESCE(t.approved_for_execution, t.approved_for_lab) AS approved_for_execution,
                COALESCE(t.safe_for_production, FALSE) AS safe_for_production,
                COALESCE(t.requires_reboot, FALSE) AS requires_reboot,
                COALESCE(t.allowed_runner_groups, '[]'::jsonb) AS allowed_runner_groups,
                t.enabled,
                t.source_file,
                t.raw_yaml
            FROM atomic_tests t
            WHERE t.id = :test_id
        """), {"test_id": test_id}).mappings().first()
        return dict(row) if row else None


def approve_atomic_test(test_id: int, approved: bool = True) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE atomic_tests
            SET approved_for_execution = :approved,
                approved_for_lab = :approved,
                updated_at = :now
            WHERE id = :test_id
            RETURNING id, technique_id, atomic_name, approved_for_lab, approved_for_execution, risk_level
        """), {"test_id": test_id, "approved": approved, "now": datetime.utcnow()}).mappings().first()
        db.commit()
        if not row:
            raise ValueError("Atomic test not found")
        return dict(row)


def update_atomic_test_risk(test_id: int, risk_level: str) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE atomic_tests
            SET risk_level = :risk_level,
                updated_at = :now
            WHERE id = :test_id
            RETURNING id, technique_id, atomic_name, approved_for_execution, risk_level
        """), {"test_id": test_id, "risk_level": risk_level, "now": datetime.utcnow()}).mappings().first()
        db.commit()
        if not row:
            raise ValueError("Atomic test not found")
        return dict(row)


def update_atomic_test_flags(test_id: int, safe_for_production: bool, requires_reboot: bool, allowed_runner_groups: list[str]) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE atomic_tests
            SET safe_for_production = :safe_for_production,
                requires_reboot = :requires_reboot,
                allowed_runner_groups = CAST(:allowed_runner_groups AS JSONB),
                updated_at = :now
            WHERE id = :test_id
            RETURNING id, technique_id, atomic_name, safe_for_production, requires_reboot, allowed_runner_groups
        """), {
            "test_id": test_id,
            "safe_for_production": safe_for_production,
            "requires_reboot": requires_reboot,
            "allowed_runner_groups": _json(allowed_runner_groups),
            "now": datetime.utcnow(),
        }).mappings().first()
        db.commit()
        if not row:
            raise ValueError("Atomic test not found")
        return dict(row)


def create_atomic_execution_preview(
    atomic_test_id: int,
    technique_id: str,
    atomic_test_number: int | None,
    runner_id: str | None,
    target_host: str | None,
    requested_by: str | None,
    command_preview: str,
    status: str,
    block_reason: str | None,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO atomic_execution_jobs (
                atomic_test_id, technique_id, atomic_test_number, runner_id, target_host,
                status, requested_by, command_preview, block_reason, payload, created_at
            ) VALUES (
                :atomic_test_id, :technique_id, :atomic_test_number, :runner_id, :target_host,
                :status, :requested_by, :command_preview, :block_reason, CAST(:payload AS JSONB), :now
            )
            RETURNING id, execution_uuid, atomic_test_id, technique_id, atomic_test_number, runner_id,
                      target_host, status, requested_by, command_preview, block_reason, payload, created_at
        """), {
            "atomic_test_id": atomic_test_id,
            "technique_id": technique_id,
            "atomic_test_number": atomic_test_number,
            "runner_id": runner_id,
            "target_host": target_host,
            "status": status,
            "requested_by": requested_by,
            "command_preview": command_preview,
            "block_reason": block_reason,
            "payload": _json(payload or {}),
            "now": datetime.utcnow(),
        }).mappings().first()
        db.commit()
        return dict(row)


def list_atomic_executions(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
            SELECT e.id, e.execution_uuid, e.atomic_test_id, e.technique_id, e.atomic_test_number,
                   e.runner_id, e.target_host, e.status, e.requested_by, e.command_preview,
                   e.block_reason, e.created_at, t.atomic_name, t.risk_level, t.executor_name
            FROM atomic_execution_jobs e
            LEFT JOIN atomic_tests t ON t.id = e.atomic_test_id
            ORDER BY e.id DESC
            LIMIT :limit OFFSET :offset
        """), {"limit": limit, "offset": offset}).mappings().all()
        return [dict(row) for row in rows]
