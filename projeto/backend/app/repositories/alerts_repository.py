from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.database.connection import get_db_session


def _now() -> datetime:
    return datetime.now()


def _to_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if value in (None, ""):
        return _now()
    raw = str(value).strip()
    try:
        # Accept ISO values from ADAudit/PowerShell. PostgreSQL timestamp is naive in this project.
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
        return parsed.replace(tzinfo=None)
    except Exception:
        return _now()


def _to_iso(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    return str(value)


def _status_label(status: int) -> str:
    return {1: "novo alarme", 2: "conhecido", 3: "finalizado"}.get(int(status or 0), "desconhecido")


def _mapping(row: Any) -> Dict[str, Any]:
    return dict(row._mapping if hasattr(row, "_mapping") else row)


def _row_to_alert(row: Any) -> Dict[str, Any]:
    m = _mapping(row)
    raw_payload = m.get("raw_payload") or {}
    status = int(m.get("status") or 0)
    ip = m.get("ip_address") or ""
    event = m.get("display_name") or m.get("event_number") or m.get("event_type") or "Inbound Alert"
    return {
        "db_id": m.get("id"),
        "id": m.get("id"),
        "alert_id": m.get("alert_uuid") or "",
        "alert_uuid": m.get("alert_uuid") or "",
        "status": status,
        "status_label": _status_label(status),
        "received_at": _to_iso(m.get("received_at")),
        "resolved_at": _to_iso(m.get("resolved_at")),
        "resolution_type": m.get("resolution_method") or "",
        "resolved_by": m.get("resolved_by") or "",
        "source_system": m.get("source_system") or "",
        "event": event,
        "event_number": m.get("event_number") or "",
        "event_type": m.get("event_type") or "",
        "event_type_text": m.get("event_type_text") or "",
        "display_name": m.get("display_name") or "",
        "username": m.get("username") or "",
        "target_user": m.get("username") or "",
        "hostname": m.get("hostname") or "",
        "source_ip": ip,
        "target_ip": ip,
        "ip_address": ip,
        "technique": m.get("mitre_technique") or "",
        "tactic": m.get("mitre_tactic") or "",
        "nist": m.get("nist_control") or "",
        "mitre_technique": m.get("mitre_technique") or "",
        "mitre_tactic": m.get("mitre_tactic") or "",
        "nist_control": m.get("nist_control") or "",
        "severity": m.get("severity") or "",
        "raw_payload": raw_payload,
        # Backward-compatible keys used by the current frontend/actions view.
        "execution_status": "idle",
        "execution_mode": "unknown",
        "last_execution_at": "",
        "last_execution_message": "",
        "playbook_name": "",
        "credential_name": "",
        "execution_id": "",
    }


def upsert_alert(alert_record: Dict[str, Any]) -> Dict[str, Any]:
    alert_uuid = str(alert_record.get("alert_id") or alert_record.get("alert_uuid") or "").strip()
    if not alert_uuid:
        raise ValueError("alert_id é obrigatório.")

    raw_payload = alert_record.get("raw_payload") or {}
    if not isinstance(raw_payload, (dict, list)):
        raw_payload = {"value": raw_payload}

    payload = {
        "alert_uuid": alert_uuid,
        "source_system": str(alert_record.get("source_system") or raw_payload.get("source_system") if isinstance(raw_payload, dict) else ""),
        "event_number": str(alert_record.get("event_number") or ""),
        "event_type": str(alert_record.get("event_type") or raw_payload.get("event_type") if isinstance(raw_payload, dict) else ""),
        "event_type_text": str(alert_record.get("event_type_text") or raw_payload.get("event_type_text") if isinstance(raw_payload, dict) else ""),
        "display_name": str(alert_record.get("display_name") or alert_record.get("event") or "Inbound Alert"),
        "username": str(alert_record.get("username") or alert_record.get("target_user") or ""),
        "hostname": str(alert_record.get("hostname") or ""),
        "ip_address": str(alert_record.get("ip_address") or alert_record.get("target_ip") or alert_record.get("source_ip") or ""),
        "mitre_tactic": str(alert_record.get("mitre_tactic") or alert_record.get("tactic") or ""),
        "mitre_technique": str(alert_record.get("mitre_technique") or alert_record.get("technique") or ""),
        "nist_control": str(alert_record.get("nist_control") or alert_record.get("nist") or ""),
        "severity": str(alert_record.get("severity") or ""),
        "status": int(alert_record.get("status") or 1),
        "raw_payload": json.dumps(raw_payload, ensure_ascii=False),
        "received_at": _to_dt(alert_record.get("received_at") or alert_record.get("date")),
    }

    with get_db_session() as session:
        row = session.execute(
            text(
                """
                INSERT INTO alerts
                    (alert_uuid, source_system, event_number, event_type, event_type_text,
                     display_name, username, hostname, ip_address, mitre_tactic,
                     mitre_technique, nist_control, severity, status, raw_payload, received_at)
                VALUES
                    (:alert_uuid, :source_system, :event_number, :event_type, :event_type_text,
                     :display_name, :username, :hostname, :ip_address, :mitre_tactic,
                     :mitre_technique, :nist_control, :severity, :status,
                     CAST(:raw_payload AS jsonb), :received_at)
                ON CONFLICT (alert_uuid) DO UPDATE SET
                    source_system = EXCLUDED.source_system,
                    event_number = EXCLUDED.event_number,
                    event_type = EXCLUDED.event_type,
                    event_type_text = EXCLUDED.event_type_text,
                    display_name = EXCLUDED.display_name,
                    username = EXCLUDED.username,
                    hostname = EXCLUDED.hostname,
                    ip_address = EXCLUDED.ip_address,
                    mitre_tactic = EXCLUDED.mitre_tactic,
                    mitre_technique = EXCLUDED.mitre_technique,
                    nist_control = EXCLUDED.nist_control,
                    severity = EXCLUDED.severity,
                    raw_payload = EXCLUDED.raw_payload
                RETURNING *
                """
            ),
            payload,
        ).fetchone()
        return _row_to_alert(row)


def list_alerts(status: Optional[int] = None, limit: int = 500) -> List[Dict[str, Any]]:
    try:
        limit = max(1, min(int(limit), 1000))
    except Exception:
        limit = 500
    where = ""
    params: Dict[str, Any] = {"limit": limit}
    if status is not None:
        where = "WHERE status = :status"
        params["status"] = int(status)
    with get_db_session() as session:
        rows = session.execute(
            text(f"SELECT * FROM alerts {where} ORDER BY received_at DESC, id DESC LIMIT :limit"),
            params,
        ).fetchall()
        return [_row_to_alert(row) for row in rows]


def list_open_alerts() -> List[Dict[str, Any]]:
    with get_db_session() as session:
        rows = session.execute(
            text("SELECT * FROM alerts WHERE status <> 3 ORDER BY received_at DESC, id DESC LIMIT 500")
        ).fetchall()
        return [_row_to_alert(row) for row in rows]


def list_resolved_alerts() -> List[Dict[str, Any]]:
    return list_alerts(status=3)


def get_alert_by_uuid(alert_uuid: str) -> Optional[Dict[str, Any]]:
    if not alert_uuid:
        return None
    with get_db_session() as session:
        row = session.execute(
            text("SELECT * FROM alerts WHERE alert_uuid = :alert_uuid LIMIT 1"),
            {"alert_uuid": str(alert_uuid)},
        ).fetchone()
        return _row_to_alert(row) if row else None


def get_latest_alert() -> Dict[str, Any]:
    with get_db_session() as session:
        row = session.execute(text("SELECT * FROM alerts ORDER BY received_at DESC, id DESC LIMIT 1")).fetchone()
        return _row_to_alert(row) if row else {}


def update_alert_status(alert_uuid: str, status: int, resolution_type: str = "", resolved_by: str = "", message: str = "") -> Dict[str, Any]:
    current = get_alert_by_uuid(alert_uuid)
    if not current:
        raise ValueError("Alerta não encontrado.")
    old_status = int(current.get("status") or 0)
    status = int(status)
    now = _now()
    with get_db_session() as session:
        row = session.execute(
            text(
                """
                UPDATE alerts
                SET status = :status,
                    resolved_at = CASE WHEN :status = 3 THEN :resolved_at ELSE resolved_at END,
                    resolved_by = CASE WHEN :status = 3 THEN :resolved_by ELSE resolved_by END,
                    resolution_method = CASE WHEN :status = 3 THEN :resolution_method ELSE resolution_method END
                WHERE alert_uuid = :alert_uuid
                RETURNING *
                """
            ),
            {
                "alert_uuid": alert_uuid,
                "status": status,
                "resolved_at": now,
                "resolved_by": resolved_by or "operator",
                "resolution_method": resolution_type or "manual",
            },
        ).fetchone()
        if not row:
            raise ValueError("Alerta não encontrado.")
        session.execute(
            text(
                """
                INSERT INTO alert_history (alert_id, old_status, new_status, action, changed_by, created_at)
                VALUES (:alert_id, :old_status, :new_status, :action, :changed_by, :created_at)
                """
            ),
            {
                "alert_id": row._mapping["id"],
                "old_status": old_status,
                "new_status": status,
                "action": message or f"Status alterado para {_status_label(status)}",
                "changed_by": resolved_by or "operator",
                "created_at": now,
            },
        )
        return _row_to_alert(row)


def mark_alert_execution_started(alert_uuid: str, playbook_name: str, credential_name: str, execution_mode: str, message: str = "") -> Dict[str, Any]:
    return update_alert_status(
        alert_uuid,
        2,
        "",
        "playbook",
        message or f"Execução iniciada: {playbook_name} / {credential_name} / {execution_mode}",
    )


def register_execution_result(alert_uuid: str, success: bool, message: str = "", resolution_type: str = "playbook") -> Dict[str, Any]:
    if success:
        return update_alert_status(alert_uuid, 3, resolution_type or "playbook", "playbook", message or "Execução concluída com sucesso.")
    current = get_alert_by_uuid(alert_uuid)
    if not current:
        raise ValueError("Alerta não encontrado.")
    with get_db_session() as session:
        session.execute(
            text(
                """
                INSERT INTO alert_history (alert_id, old_status, new_status, action, changed_by, created_at)
                VALUES (:alert_id, :old_status, :new_status, :action, :changed_by, :created_at)
                """
            ),
            {
                "alert_id": current.get("db_id"),
                "old_status": current.get("status"),
                "new_status": current.get("status"),
                "action": message or "Execução finalizada com falha.",
                "changed_by": "playbook",
                "created_at": _now(),
            },
        )
    return current


def alert_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS new,
                    SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) AS known,
                    SUM(CASE WHEN status = 3 THEN 1 ELSE 0 END) AS resolved
                FROM alerts
                """
            )
        ).fetchone()
        m = _mapping(rows)
        return {"total": int(m.get("total") or 0), "new": int(m.get("new") or 0), "known": int(m.get("known") or 0), "resolved": int(m.get("resolved") or 0)}


def report_mitre_map() -> List[Dict[str, Any]]:
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT COALESCE(NULLIF(mitre_technique, ''), 'Não mapeado') AS label, COUNT(*) AS count
                FROM alerts
                GROUP BY label
                ORDER BY count DESC, label ASC
                """
            )
        ).fetchall()
        return [{"label": r._mapping["label"], "count": int(r._mapping["count"] or 0)} for r in rows]


def report_nist_map() -> List[Dict[str, Any]]:
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT COALESCE(NULLIF(nist_control, ''), 'Não mapeado') AS label, COUNT(*) AS count
                FROM alerts
                GROUP BY label
                ORDER BY count DESC, label ASC
                """
            )
        ).fetchall()
        return [{"label": r._mapping["label"], "count": int(r._mapping["count"] or 0)} for r in rows]


def list_alert_history(alert_uuid: str) -> List[Dict[str, Any]]:
    alert = get_alert_by_uuid(alert_uuid)
    if not alert:
        return []
    with get_db_session() as session:
        rows = session.execute(
            text(
                """
                SELECT * FROM alert_history
                WHERE alert_id = :alert_id
                ORDER BY created_at DESC, id DESC
                LIMIT 100
                """
            ),
            {"alert_id": alert.get("db_id")},
        ).fetchall()
        result = []
        for row in rows:
            m = _mapping(row)
            result.append({
                "id": m.get("id"),
                "old_status": m.get("old_status"),
                "new_status": m.get("new_status"),
                "action": m.get("action") or "",
                "changed_by": m.get("changed_by") or "",
                "created_at": _to_iso(m.get("created_at")),
            })
        return result
