from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.database.connection import get_db_session
from app.repositories.credentials_repository import get_stored_credential_by_name
from app.repositories.playbooks_repository import get_playbook_by_name


def _to_iso(value: Any) -> str:
    return value.isoformat() if value else ""


def _row_to_dict(row: Any) -> Dict[str, Any]:
    mapping = row._mapping if hasattr(row, "_mapping") else row
    return {
        "id": str(mapping.get("id")),
        "alert_id": str(mapping.get("alert_id") or ""),
        "playbook_id": str(mapping.get("playbook_id") or ""),
        "playbook_name": mapping.get("playbook_name") or "",
        "credential_id": str(mapping.get("credential_id") or ""),
        "credential_name": mapping.get("credential_name") or "",
        "target": mapping.get("target") or "",
        "variables": mapping.get("variables") or {},
        "status": mapping.get("status") or "pending",
        "output": mapping.get("output") or "",
        "error": mapping.get("error") or "",
        "executed_by": mapping.get("executed_by") or "",
        "started_at": _to_iso(mapping.get("started_at")),
        "finished_at": _to_iso(mapping.get("finished_at")),
    }


def _resolve_playbook_id(playbook_name: str) -> Optional[int]:
    playbook = get_playbook_by_name(playbook_name, include_content=False)
    if not playbook:
        return None
    try:
        return int(str(playbook.get("id") or ""))
    except Exception:
        return None


def _resolve_credential_id(credential_name: str) -> Optional[int]:
    if not credential_name:
        return None
    credential = get_stored_credential_by_name(credential_name)
    if not credential:
        return None
    try:
        return int(str(credential.get("id") or ""))
    except Exception:
        return None


def create_playbook_execution(payload: Dict[str, Any]) -> Dict[str, Any]:
    playbook_name = str(payload.get("playbook_name") or payload.get("script_name") or "").strip()
    credential_name = str(payload.get("credential_name") or "").strip()
    target = str(payload.get("target") or "").strip()
    variables = payload.get("variables") or {}
    status = str(payload.get("status") or "running").strip() or "running"
    executed_by = str(payload.get("executed_by") or "system").strip() or "system"
    alert_id_raw = payload.get("alert_id")

    playbook_id = payload.get("playbook_id") or _resolve_playbook_id(playbook_name)
    credential_id = payload.get("credential_id") or _resolve_credential_id(credential_name)

    try:
        playbook_id = int(playbook_id) if playbook_id not in (None, "") else None
    except Exception:
        playbook_id = None
    try:
        credential_id = int(credential_id) if credential_id not in (None, "") else None
    except Exception:
        credential_id = None
    try:
        alert_id = int(alert_id_raw) if alert_id_raw not in (None, "") else None
    except Exception:
        alert_id = None

    now = datetime.now()
    with get_db_session() as session:
        result = session.execute(
            text(
                """
                INSERT INTO playbook_executions
                    (alert_id, playbook_id, credential_id, target, variables, status,
                     output, error, executed_by, started_at, finished_at)
                VALUES
                    (:alert_id, :playbook_id, :credential_id, :target, CAST(:variables AS jsonb), :status,
                     '', '', :executed_by, :started_at, NULL)
                RETURNING id
                """
            ),
            {
                "alert_id": alert_id,
                "playbook_id": playbook_id,
                "credential_id": credential_id,
                "target": target,
                "variables": json.dumps(variables, ensure_ascii=False),
                "status": status,
                "executed_by": executed_by,
                "started_at": now,
            },
        )
        execution_id = int(result.scalar_one())
    execution = get_playbook_execution_by_id(execution_id)
    if not execution:
        raise ValueError("Execução criada, mas não foi possível recarregar o registro.")
    execution["playbook_name"] = playbook_name
    execution["credential_name"] = credential_name
    return execution


def update_playbook_execution_result(execution_id: str | int, result_payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        eid = int(str(execution_id))
    except Exception:
        raise ValueError("ID de execução inválido.")

    success = bool(result_payload.get("success"))
    pending_external = bool(result_payload.get("pending_external"))
    if pending_external:
        status = "pending_external"
    elif success:
        status = "success"
    else:
        status = "failed"

    output_parts: List[str] = []
    if result_payload.get("message"):
        output_parts.append(str(result_payload.get("message")))
    if result_payload.get("stdout"):
        output_parts.append(str(result_payload.get("stdout")))
    output = "\n".join(part for part in output_parts if part).strip()
    error = str(result_payload.get("stderr") or result_payload.get("error") or "").strip()

    with get_db_session() as session:
        rowcount = session.execute(
            text(
                """
                UPDATE playbook_executions
                SET status = :status,
                    output = :output,
                    error = :error,
                    finished_at = :finished_at
                WHERE id = :id
                """
            ),
            {
                "id": eid,
                "status": status,
                "output": output[-8000:],
                "error": error[-8000:],
                "finished_at": datetime.now(),
            },
        ).rowcount
        if not rowcount:
            raise ValueError("Execução não encontrada.")
    execution = get_playbook_execution_by_id(eid)
    if not execution:
        raise ValueError("Execução atualizada, mas não foi possível recarregar o registro.")
    return execution


def get_playbook_execution_by_id(execution_id: str | int) -> Optional[Dict[str, Any]]:
    try:
        eid = int(str(execution_id))
    except Exception:
        return None
    with get_db_session() as session:
        row = session.execute(
            text(
                """
                SELECT pe.id, pe.alert_id, pe.playbook_id, p.name AS playbook_name,
                       pe.credential_id, sc.name AS credential_name,
                       pe.target, pe.variables, pe.status, pe.output, pe.error,
                       pe.executed_by, pe.started_at, pe.finished_at
                FROM playbook_executions pe
                LEFT JOIN playbooks p ON p.id = pe.playbook_id
                LEFT JOIN stored_credentials sc ON sc.id = pe.credential_id
                WHERE pe.id = :id
                LIMIT 1
                """
            ),
            {"id": eid},
        ).fetchone()
        return _row_to_dict(row) if row else None


def list_playbook_executions(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 100
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT pe.id, pe.alert_id, pe.playbook_id, p.name AS playbook_name,
                       pe.credential_id, sc.name AS credential_name,
                       pe.target, pe.variables, pe.status, pe.output, pe.error,
                       pe.executed_by, pe.started_at, pe.finished_at
                FROM playbook_executions pe
                LEFT JOIN playbooks p ON p.id = pe.playbook_id
                LEFT JOIN stored_credentials sc ON sc.id = pe.credential_id
                ORDER BY pe.started_at DESC, pe.id DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).fetchall()
        return [_row_to_dict(row) for row in rows]
