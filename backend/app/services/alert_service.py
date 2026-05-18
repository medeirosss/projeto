from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from app.repositories.alerts_repository import (
    alert_summary,
    get_alert_by_uuid,
    get_latest_alert,
    list_alert_history,
    list_alerts,
    list_open_alerts,
    list_resolved_alerts,
    mark_alert_execution_started,
    register_execution_result,
    report_mitre_map,
    report_nist_map,
    update_alert_status,
    upsert_alert,
)


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def generate_alert_id() -> str:
    return f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"


def ensure_alert_id(value: Any = None) -> str:
    text = str(value or "").strip()
    return text if text else generate_alert_id()


def _looks_normalized(payload: Dict[str, Any]) -> bool:
    keys = {"display_name", "event_number", "target_user", "username", "mitre_technique", "technique", "normalized_context"}
    return any(key in payload for key in keys)


def _normalize_if_needed(payload: Dict[str, Any]) -> Dict[str, Any]:
    if _looks_normalized(payload):
        return payload

    from app.services.alert_normalizer import normalize_inbound_alert

    return normalize_inbound_alert(payload or {})


def build_alert_record(normalized: Dict[str, Any]) -> Dict[str, Any]:
    received_at = str(normalized.get("received_at") or normalized.get("date") or _now_iso())
    source_ip = str(normalized.get("source_ip") or normalized.get("ip") or "").strip()
    hostname = str(normalized.get("hostname") or normalized.get("host") or normalized.get("machine") or "").strip()
    raw_payload = normalized.get("raw_payload") or normalized
    normalized_without_raw = {k: v for k, v in normalized.items() if k != "raw_payload"}

    return {
        "alert_id": ensure_alert_id(normalized.get("alert_id")),
        "status": int(normalized.get("status") or 1),
        "received_at": received_at,
        "event": str(normalized.get("event") or normalized.get("display_name") or normalized.get("event_number") or "Inbound Alert"),
        "event_number": str(normalized.get("event_number") or ""),
        "event_type": str(normalized.get("event_type") or ""),
        "event_type_text": str(normalized.get("event_type_text") or ""),
        "display_name": str(normalized.get("display_name") or normalized.get("event") or "Inbound Alert"),
        "username": str(normalized.get("username") or normalized.get("target_user") or ""),
        "target_user": str(normalized.get("target_user") or normalized.get("username") or ""),
        "actor_user": str(normalized.get("actor_user") or ""),
        "technique": str(normalized.get("technique") or normalized.get("mitre_technique") or ""),
        "tactic": str(normalized.get("tactic") or normalized.get("mitre_tactic") or ""),
        "nist": str(normalized.get("nist") or normalized.get("nist_control") or ""),
        "mitre_technique": str(normalized.get("mitre_technique") or normalized.get("technique") or ""),
        "mitre_tactic": str(normalized.get("mitre_tactic") or normalized.get("tactic") or ""),
        "nist_control": str(normalized.get("nist_control") or normalized.get("nist") or ""),
        "severity": str(normalized.get("severity") or "Media"),
        "source_system": str(normalized.get("source_system") or ""),
        "source_ip": source_ip,
        "target_ip": str(normalized.get("target_ip") or normalized.get("ip_address") or source_ip or ""),
        "ip_address": str(normalized.get("ip_address") or normalized.get("target_ip") or source_ip or ""),
        "hostname": hostname,
        "recommendation": str(normalized.get("recommendation") or ""),
        "raw_payload": {
            "normalized": normalized_without_raw,
            "original": raw_payload,
        },
    }


def create_alert_from_inbound(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_if_needed(payload or {})
    alert_id = ensure_alert_id(normalized.get("alert_id"))
    normalized["alert_id"] = alert_id

    existing = get_alert_by_id(alert_id)
    if existing:
        return existing

    return upsert_alert(build_alert_record(normalized))


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    return get_alert_by_uuid(alert_id)


def send_n8n_webhook(settings: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    mail_cfg = settings.get("mail_server", {})
    url = mail_cfg.get("n8n_webhook_url", "").strip()
    if not mail_cfg.get("whatsapp_enabled") or not url:
        return {"sent": False, "reason": "whatsapp_or_url_disabled"}
    response = requests.post(url, json=payload, timeout=15)
    return {"sent": response.ok, "status_code": response.status_code}
