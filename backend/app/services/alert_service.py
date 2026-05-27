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
    update_alert_connectivity_status,
    upsert_alert,
)

from app.repositories.runner_repository import (
    create_runner_job,
    create_validation_job,
    get_latest_validation_for_alert,
    link_validation_to_runner_job,
)

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def generate_alert_id() -> str:
    return f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"


def ensure_alert_id(value: Any = None) -> str:
    text = str(value or "").strip()
    return text if text else generate_alert_id()


def _looks_normalized(payload: Dict[str, Any]) -> bool:
    # Payload bruto vindo de ADAudit/SIEM normalmente possui event_number, username,
    # account_name etc. Isso NÃO significa que já passou pelo normalizer.
    # Consideramos normalizado apenas quando já existem campos enriquecidos.
    required_normalized_keys = {
        "display_name",
        "mitre_technique",
        "mitre_tactic",
        "nist_control",
        "recommendation",
        "normalized_context",
    }
    return any(key in payload for key in required_normalized_keys)


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

    record = {
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
        "risk_score": normalized.get("risk_score"),
        "risk_level": normalized.get("risk_level"),
        "raw_payload": {
            "normalized": normalized_without_raw,
            "original": raw_payload,
        },
    }

    return enrich_alert_risk(record)



def _is_internal_ip(ip_value: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(str(ip_value).strip())
        return ip.is_private
    except Exception:
        return False


def _alert_target_ip(alert: Dict[str, Any]) -> str:
    return str(alert.get("ip_address") or alert.get("target_ip") or alert.get("source_ip") or "").strip()


def _severity_score(severity: Any) -> int:
    sev = str(severity or "").strip().lower()
    if "crit" in sev:
        return 45
    if "alta" in sev or "high" in sev:
        return 35
    if "media" in sev or "média" in sev or "medium" in sev:
        return 20
    if "baixa" in sev or "low" in sev:
        return 10
    return 10


def _event_score(event_number: Any) -> int:
    event = str(event_number or "").strip()
    high_risk_events = {
        "4728",  # Member added to a security-enabled global group
        "4732",  # Member added to a security-enabled local group
        "4756",  # Member added to a security-enabled universal group
    }
    medium_high_events = {
        "4720",  # User account created
        "4726",  # User account deleted
        "4738",  # User account changed
        "4740",  # User account locked out
    }
    medium_events = {
        "4625",  # Failed logon
        "4624",  # Successful logon
    }

    if event in high_risk_events:
        return 35
    if event in medium_high_events:
        return 25
    if event in medium_events:
        return 15
    return 0


def calculate_risk_score(alert_record: Dict[str, Any]) -> int:
    score = 0

    score += _severity_score(alert_record.get("severity"))
    score += _event_score(alert_record.get("event_number"))

    if alert_record.get("mitre_technique") or alert_record.get("technique"):
        score += 10

    if alert_record.get("ip_address") or alert_record.get("target_ip") or alert_record.get("source_ip"):
        score += 5

    if alert_record.get("source_system"):
        score += 5

    return max(0, min(int(score), 100))


def risk_level_from_score(score: int) -> str:
    score = int(score or 0)
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def enrich_alert_risk(alert_record: Dict[str, Any]) -> Dict[str, Any]:
    explicit_score = alert_record.get("risk_score")
    try:
        score = int(explicit_score) if explicit_score not in (None, "") else calculate_risk_score(alert_record)
    except Exception:
        score = calculate_risk_score(alert_record)

    alert_record["risk_score"] = max(0, min(score, 100))
    alert_record["risk_level"] = str(alert_record.get("risk_level") or risk_level_from_score(alert_record["risk_score"]))
    return alert_record

def create_alert_from_inbound(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_if_needed(payload or {})
    alert_id = ensure_alert_id(normalized.get("alert_id"))
    normalized["alert_id"] = alert_id

    existing = get_alert_by_id(alert_id)
    if existing:
        return existing

    alert = upsert_alert(build_alert_record(normalized))

    # Cria a validação automaticamente, mas não executa.
    # A execução será acionada manualmente pelo analista na tela de detalhes.
    try:
        target_ip = _alert_target_ip(alert)
        if target_ip and _is_internal_ip(target_ip):
            create_validation_job(
                runner_job_id=None,
                runner_id=None,
                validation_type="host_reachable",
                target=target_ip,
                expected_state={"reachable": True, "ping_count": 4, "min_success": 3},
                alert_id=alert.get("db_id"),
                status="pending_manual",
            )
    except Exception as exc:
        print(f"[CONNECTIVITY_VALIDATION_CREATE_ERROR] {exc}")

    return alert


def run_connectivity_validation_for_alert(alert_id: str) -> Dict[str, Any]:
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise ValueError("Alerta não encontrado.")

    target_ip = _alert_target_ip(alert)
    if not target_ip:
        raise ValueError("Alerta não possui IP para validação.")

    if not _is_internal_ip(target_ip):
        update_alert_connectivity_status(
            alert.get("alert_uuid") or alert.get("alert_id"),
            "check_failed",
            "Validação bloqueada: IP fora do escopo interno permitido.",
        )
        raise ValueError("IP fora do escopo interno permitido.")

    validation = get_latest_validation_for_alert(int(alert.get("db_id")), "host_reachable")
    if not validation:
        validation = create_validation_job(
            runner_job_id=None,
            runner_id=None,
            validation_type="host_reachable",
            target=target_ip,
            expected_state={"reachable": True, "ping_count": 4, "min_success": 3},
            alert_id=alert.get("db_id"),
            status="pending_manual",
        )

    runner_job = create_runner_job(
        runner_id=None,
        job_type="validation",
        target=target_ip,
        payload={
            "validation_type": "host_reachable",
            "ping_count": 4,
            "min_success": 3,
            "alert_id": alert.get("db_id"),
            "alert_uuid": alert.get("alert_uuid") or alert.get("alert_id"),
            "validation_id": validation.get("id"),
        },
    )

    validation = link_validation_to_runner_job(
        validation_id=int(validation["id"]),
        runner_job_id=int(runner_job["id"]),
        status="queued",
    )

    updated_alert = update_alert_connectivity_status(
        alert.get("alert_uuid") or alert.get("alert_id"),
        "checking",
        "Validação de conectividade enviada ao Runner.",
    )

    return {
        "success": True,
        "alert": updated_alert or alert,
        "runner_job": runner_job,
        "validation": validation,
    }


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    return get_alert_by_uuid(alert_id)


def send_n8n_webhook(settings: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    mail_cfg = settings.get("mail_server", {})
    url = mail_cfg.get("n8n_webhook_url", "").strip()
    if not mail_cfg.get("whatsapp_enabled") or not url:
        return {"sent": False, "reason": "whatsapp_or_url_disabled"}
    response = requests.post(url, json=payload, timeout=15)
    return {"sent": response.ok, "status_code": response.status_code}
