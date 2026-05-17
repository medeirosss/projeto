from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.database.connection import get_db_session


def _json_default(value: Any) -> Any:
    return value if value is not None else []


def _row_to_dict(row: Any, include_content: bool = False) -> Dict[str, Any]:
    mapping = row._mapping if hasattr(row, "_mapping") else row
    item: Dict[str, Any] = {
        "id": str(mapping.get("id")),
        "name": mapping.get("name") or "",
        "description": mapping.get("description") or "",
        "script_type": mapping.get("script_type") or "",
        "extension": mapping.get("script_type") or "",
        "required_variables": mapping.get("required_variables") or [],
        "metadata": mapping.get("metadata") or {},
        "enabled": bool(mapping.get("enabled", True)),
        "created_at": mapping.get("created_at").isoformat() if mapping.get("created_at") else "",
        "updated_at": mapping.get("updated_at").isoformat() if mapping.get("updated_at") else "",
    }
    if include_content:
        item["script_content"] = mapping.get("script_content") or ""
    return item


def list_playbooks() -> List[Dict[str, Any]]:
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT id, name, description, script_type, required_variables, metadata,
                       enabled, created_at, updated_at
                FROM playbooks
                WHERE enabled = TRUE
                ORDER BY name ASC
                """
            )
        ).fetchall()
        return [_row_to_dict(row) for row in rows]


def get_playbook_by_name(name: str, include_content: bool = True) -> Optional[Dict[str, Any]]:
    name_key = (name or "").strip()
    if not name_key:
        return None
    columns = "id, name, description, script_type, required_variables, metadata, enabled, created_at, updated_at"
    if include_content:
        columns += ", script_content"
    with get_db_session() as session:
        row = session.execute(
            text(
                f"""
                SELECT {columns}
                FROM playbooks
                WHERE LOWER(name) = LOWER(:name) AND enabled = TRUE
                LIMIT 1
                """
            ),
            {"name": name_key},
        ).fetchone()
        return _row_to_dict(row, include_content=include_content) if row else None


def get_playbook_by_id(playbook_id: str | int, include_content: bool = True) -> Optional[Dict[str, Any]]:
    try:
        pid = int(str(playbook_id))
    except Exception:
        return None
    columns = "id, name, description, script_type, required_variables, metadata, enabled, created_at, updated_at"
    if include_content:
        columns += ", script_content"
    with get_db_session() as session:
        row = session.execute(
            text(
                f"""
                SELECT {columns}
                FROM playbooks
                WHERE id = :id AND enabled = TRUE
                LIMIT 1
                """
            ),
            {"id": pid},
        ).fetchone()
        return _row_to_dict(row, include_content=include_content) if row else None


def save_playbook(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("Informe o nome do playbook.")
    script_content = str(payload.get("script_content") or payload.get("content") or "")
    if not script_content.strip():
        raise ValueError("O conteúdo do script não pode ser vazio.")
    script_type = str(payload.get("script_type") or payload.get("extension") or "").strip().lower()
    if script_type not in {".ps1", ".sh"}:
        raise ValueError("Somente scripts .ps1 e .sh são suportados.")

    description = str(payload.get("description") or "").strip()
    required_variables = payload.get("required_variables") or []
    metadata = payload.get("metadata") or {}
    now = datetime.now()

    with get_db_session() as session:
        existing = session.execute(
            text("SELECT id FROM playbooks WHERE LOWER(name) = LOWER(:name) LIMIT 1"),
            {"name": name},
        ).fetchone()
        if existing:
            target_id = int(existing._mapping["id"])
            session.execute(
                text(
                    """
                    UPDATE playbooks
                    SET name = :name,
                        description = :description,
                        script_type = :script_type,
                        script_content = :script_content,
                        required_variables = CAST(:required_variables AS jsonb),
                        metadata = CAST(:metadata AS jsonb),
                        enabled = TRUE,
                        updated_at = :updated_at
                    WHERE id = :id
                    """
                ),
                {
                    "id": target_id,
                    "name": name,
                    "description": description,
                    "script_type": script_type,
                    "script_content": script_content,
                    "required_variables": __import__('json').dumps(required_variables, ensure_ascii=False),
                    "metadata": __import__('json').dumps(metadata, ensure_ascii=False),
                    "updated_at": now,
                },
            )
        else:
            result = session.execute(
                text(
                    """
                    INSERT INTO playbooks
                        (name, description, script_type, script_content, required_variables, metadata,
                         enabled, created_at, updated_at)
                    VALUES
                        (:name, :description, :script_type, :script_content,
                         CAST(:required_variables AS jsonb), CAST(:metadata AS jsonb),
                         TRUE, :created_at, :updated_at)
                    RETURNING id
                    """
                ),
                {
                    "name": name,
                    "description": description,
                    "script_type": script_type,
                    "script_content": script_content,
                    "required_variables": __import__('json').dumps(required_variables, ensure_ascii=False),
                    "metadata": __import__('json').dumps(metadata, ensure_ascii=False),
                    "created_at": now,
                    "updated_at": now,
                },
            )
            target_id = int(result.scalar_one())

    saved = get_playbook_by_id(target_id, include_content=False)
    if not saved:
        raise ValueError("Playbook salvo, mas não foi possível recarregar o registro.")
    return saved


def disable_playbook_by_name(name: str) -> bool:
    name_key = (name or "").strip()
    if not name_key:
        return False
    with get_db_session() as session:
        result = session.execute(
            text(
                """
                UPDATE playbooks
                SET enabled = FALSE, updated_at = :updated_at
                WHERE LOWER(name) = LOWER(:name) AND enabled = TRUE
                """
            ),
            {"name": name_key, "updated_at": datetime.now()},
        )
        return bool(result.rowcount)
