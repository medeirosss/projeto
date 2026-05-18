from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy import text

from app.database.connection import get_db_session


def save_license_status(status: Dict[str, Any]) -> None:
    payload = status.get("raw_license") or {}
    modules = status.get("modules") or {}
    with get_db_session() as db:
        db.execute(
            text(
                """
                INSERT INTO license_status (
                    license_id, customer_id, customer_name, domain_name,
                    license_type, license_mode, expires_at, status, status_message,
                    modules, max_users, max_endpoints, last_validation_at, raw_license
                ) VALUES (
                    :license_id, :customer_id, :customer_name, :domain_name,
                    :license_type, :license_mode, :expires_at, :status, :status_message,
                    CAST(:modules AS JSONB), :max_users, :max_endpoints, :last_validation_at, CAST(:raw_license AS JSONB)
                )
                """
            ),
            {
                "license_id": status.get("license_id"),
                "customer_id": status.get("customer_id"),
                "customer_name": status.get("customer_name"),
                "domain_name": status.get("domain_name"),
                "license_type": status.get("license_type"),
                "license_mode": status.get("license_mode"),
                "expires_at": status.get("expires_at"),
                "status": status.get("status", "unknown"),
                "status_message": status.get("status_message"),
                "modules": __import__("json").dumps(modules),
                "max_users": status.get("max_users"),
                "max_endpoints": status.get("max_endpoints"),
                "last_validation_at": status.get("last_validation_at") or datetime.utcnow(),
                "raw_license": __import__("json").dumps(payload),
            },
        )
