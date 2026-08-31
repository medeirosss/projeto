from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
import json

from sqlalchemy import text

from app.database.connection import get_db_session


def _json_load(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value in (None, ''):
        return {}
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _row_to_dict(row: Any) -> Dict[str, Any]:
    mapping = row._mapping if hasattr(row, "_mapping") else row
    return {
        "id": str(mapping.get("id")),
        "name": mapping.get("name") or "",
        "type": mapping.get("credential_type") or "generic",
        "credential_type": mapping.get("credential_type") or "generic",
        "username": mapping.get("username") or "",
        "domain": mapping.get("domain") or "",
        "secret_encrypted": mapping.get("secret_encrypted") or "",
        "description": mapping.get("description") or "",
        "metadata": _json_load(mapping.get("metadata")),
        "enabled": bool(mapping.get("enabled", True)),
        "created_at": mapping.get("created_at").isoformat() if mapping.get("created_at") else "",
        "updated_at": mapping.get("updated_at").isoformat() if mapping.get("updated_at") else "",
    }


def ensure_credentials_schema() -> None:
    """Small forward-compatible schema guard for installs upgraded without down -v."""
    with get_db_session() as session:
        session.execute(text("ALTER TABLE stored_credentials ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb"))


def list_stored_credentials() -> List[Dict[str, Any]]:
    ensure_credentials_schema()
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT id, name, credential_type, username, domain, secret_encrypted,
                       description, metadata, enabled, created_at, updated_at
                FROM stored_credentials
                WHERE enabled = TRUE
                ORDER BY name ASC
                """
            )
        ).fetchall()
        return [_row_to_dict(row) for row in rows]


def get_stored_credential_by_name(name: str) -> Optional[Dict[str, Any]]:
    ensure_credentials_schema()
    name_key = (name or "").strip()
    if not name_key:
        return None
    with get_db_session() as session:
        row = session.execute(
            text(
                """
                SELECT id, name, credential_type, username, domain, secret_encrypted,
                       description, metadata, enabled, created_at, updated_at
                FROM stored_credentials
                WHERE LOWER(name) = LOWER(:name) AND enabled = TRUE
                LIMIT 1
                """
            ),
            {"name": name_key},
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_stored_credential_by_id(credential_id: str | int) -> Optional[Dict[str, Any]]:
    ensure_credentials_schema()
    try:
        cid = int(str(credential_id))
    except Exception:
        return None
    with get_db_session() as session:
        row = session.execute(
            text(
                """
                SELECT id, name, credential_type, username, domain, secret_encrypted,
                       description, metadata, enabled, created_at, updated_at
                FROM stored_credentials
                WHERE id = :id AND enabled = TRUE
                LIMIT 1
                """
            ),
            {"id": cid},
        ).fetchone()
        return _row_to_dict(row) if row else None


def save_stored_credential(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_credentials_schema()
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("Informe o nome da credencial.")

    credential_id_raw = str(payload.get("id") or "").strip()
    credential_id: Optional[int] = None
    if credential_id_raw:
        try:
            credential_id = int(credential_id_raw)
        except ValueError:
            credential_id = None

    username = str(payload.get("username") or "").strip()
    domain = str(payload.get("domain") or "").strip()
    credential_type = str(payload.get("type") or payload.get("credential_type") or "generic").strip() or "generic"
    description = str(payload.get("description") or "").strip()
    secret_encrypted = str(payload.get("secret_encrypted") or "")
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    metadata_json = json.dumps(metadata, ensure_ascii=False)

    now = datetime.now()
    with get_db_session() as session:
        existing = None
        if credential_id:
            existing = session.execute(
                text("SELECT id, secret_encrypted FROM stored_credentials WHERE id = :id LIMIT 1"),
                {"id": credential_id},
            ).fetchone()
        if existing is None:
            existing = session.execute(
                text("SELECT id, secret_encrypted FROM stored_credentials WHERE LOWER(name) = LOWER(:name) LIMIT 1"),
                {"name": name},
            ).fetchone()

        if existing:
            existing_id = int(existing._mapping["id"])
            current_secret = existing._mapping.get("secret_encrypted") or ""
            final_secret = secret_encrypted if secret_encrypted else current_secret
            session.execute(
                text(
                    """
                    UPDATE stored_credentials
                    SET name = :name,
                        credential_type = :credential_type,
                        username = :username,
                        domain = :domain,
                        secret_encrypted = :secret_encrypted,
                        description = :description,
                        metadata = CAST(:metadata AS jsonb),
                        enabled = TRUE,
                        updated_at = :updated_at
                    WHERE id = :id
                    """
                ),
                {
                    "id": existing_id,
                    "name": name,
                    "credential_type": credential_type,
                    "username": username,
                    "domain": domain,
                    "secret_encrypted": final_secret,
                    "description": description,
                    "metadata": metadata_json,
                    "updated_at": now,
                },
            )
            target_id = existing_id
        else:
            result = session.execute(
                text(
                    """
                    INSERT INTO stored_credentials
                        (name, credential_type, username, domain, secret_encrypted, description, metadata, enabled, created_at, updated_at)
                    VALUES
                        (:name, :credential_type, :username, :domain, :secret_encrypted, :description, CAST(:metadata AS jsonb), TRUE, :created_at, :updated_at)
                    RETURNING id
                    """
                ),
                {
                    "name": name,
                    "credential_type": credential_type,
                    "username": username,
                    "domain": domain,
                    "secret_encrypted": secret_encrypted,
                    "description": description,
                    "metadata": metadata_json,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            target_id = int(result.scalar_one())

    saved = get_stored_credential_by_id(target_id)
    if not saved:
        raise ValueError("Credencial salva, mas não foi possível recarregar o registro.")
    return saved


def disable_stored_credential(credential_id: str | int) -> bool:
    ensure_credentials_schema()
    try:
        cid = int(str(credential_id))
    except Exception:
        return False
    with get_db_session() as session:
        result = session.execute(
            text(
                """
                UPDATE stored_credentials
                SET enabled = FALSE, updated_at = :updated_at
                WHERE id = :id AND enabled = TRUE
                """
            ),
            {"id": cid, "updated_at": datetime.now()},
        )
        return bool(result.rowcount)
