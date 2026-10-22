from __future__ import annotations

import json
from typing import Any, Dict

from sqlalchemy import text

from app.database.connection import get_db_session


def ensure_settings_schema() -> None:
    with get_db_session() as db:
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS app_settings (
                id SERIAL PRIMARY KEY,
                module VARCHAR(100) NOT NULL,
                setting_key VARCHAR(150) NOT NULL,
                setting_value TEXT,
                encrypted BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(module, setting_key)
            )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_app_settings_module_key ON app_settings(module, setting_key)"))


def get_settings_rows() -> Dict[str, Any]:
    ensure_settings_schema()
    with get_db_session() as db:
        rows = db.execute(
            text("""
                SELECT setting_key, setting_value
                FROM app_settings
                WHERE module = 'core'
            """)
        ).mappings().all()
    data: Dict[str, Any] = {}
    for row in rows:
        value = row.get("setting_value")
        try:
            data[row["setting_key"]] = json.loads(value) if value not in (None, "") else None
        except Exception:
            data[row["setting_key"]] = value
    return data


def save_settings_rows(settings: Dict[str, Any]) -> None:
    ensure_settings_schema()
    payload = settings or {}
    with get_db_session() as db:
        for key, value in payload.items():
            db.execute(
                text("""
                    INSERT INTO app_settings(module, setting_key, setting_value, encrypted, updated_at)
                    VALUES('core', :setting_key, :setting_value, false, CURRENT_TIMESTAMP)
                    ON CONFLICT(module, setting_key)
                    DO UPDATE SET setting_value = EXCLUDED.setting_value,
                                  encrypted = EXCLUDED.encrypted,
                                  updated_at = CURRENT_TIMESTAMP
                """),
                {"setting_key": key, "setting_value": json.dumps(value, ensure_ascii=False)},
            )


def clear_settings() -> None:
    ensure_settings_schema()
    with get_db_session() as db:
        db.execute(text("DELETE FROM app_settings WHERE module = 'core'"))
