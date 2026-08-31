from __future__ import annotations

from datetime import datetime
from sqlalchemy import text

from app.database.connection import SessionLocal


def update_alert_automation_status(
    alert_id: str,
    automation_status: str,
    automation_message: str,
):
    """
    Atualiza apenas a tag/metadados de automação do alerta.
    Não altera o status principal do alerta: novo/conhecido/finalizado continuam manuais.
    """
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE alerts
            SET automation_status = :automation_status,
                automation_message = :automation_message,
                automation_at = :automation_at
            WHERE alert_uuid = :alert_id
               OR id::text = :alert_id
            RETURNING id, alert_uuid, status,
                      automation_status, automation_message, automation_at
        """), {
            "alert_id": alert_id,
            "automation_status": automation_status,
            "automation_message": automation_message,
            "automation_at": datetime.utcnow(),
        }).mappings().first()

        db.commit()
        return dict(row) if row else None
