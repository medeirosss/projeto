from __future__ import annotations

from app.repositories.alert_automation_repository import update_alert_automation_status


def mark_alert_automation_from_validation(alert_id: str | None, validation_status: str):
    if not alert_id:
        return None

    if validation_status == "success":
        return update_alert_automation_status(
            alert_id=alert_id,
            automation_status="executed_ok",
            automation_message="Automação executada OK",
        )

    if validation_status in ["failed", "error"]:
        return update_alert_automation_status(
            alert_id=alert_id,
            automation_status="executed_failed",
            automation_message="Automação executada com falha",
        )

    return None
