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



def _is_internal_ip(ip_value: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(str(ip_value).strip())
        return ip.is_private
    except Exception:
        return False


def _alert_target_ip(alert: Dict[str, Any]) -> str:
    return str(alert.get("ip_address") or alert.get("target_ip") or alert.get("source_ip") or "").strip()



def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def calculate_alert_risk(alert_record: Dict[str, Any]) -> tuple[int, str]:
    """Calcula risco inicial do alerta para priorização operacional.

    Regra simples e determinística para MVP:
    - Severidade alta/critica tem maior peso.
    - Eventos de identidade/privilegio aumentam risco.
    - Presença de IP e mapeamento MITRE aumentam contexto.
    """
    score = 0
    severity = _normalize_text(alert_record.get("severity"))
    event_number = str(alert_record.get("event_number") or "").strip()

    if "crit" in severity:
        score += 50
    elif "alta" in severity or "high" in severity:
        score += 40
    elif "media" in severity or "média" in severity or "medium" in severity:
        score += 20
    elif "baixa" in severity or "low" in severity:
        score += 10

    if event_number in {"4728", "4732", "4756"}:  # adição em grupo privilegiado/local/global/universal
        score += 40
    elif event_number == "4720":  # usuário criado
        score += 30
    elif event_number == "4625":  # falha de login
        score += 20
    elif event_number in {"4726", "4729", "4733", "4757"}:
        score += 15

    if alert_record.get("ip_address") or alert_record.get("target_ip") or alert_record.get("source_ip"):
        score += 10

    if alert_record.get("mitre_technique") or alert_record.get("technique"):
        score += 10

    score = max(0, min(int(score), 100))

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return score, level


def build_alert_context(alert_record: Dict[str, Any], connectivity_status: str | None = None) -> tuple[str, str]:
    """Gera contexto operacional em português para o analista.

    O contexto é propositalmente curto para aparecer no detalhe do alerta.
    """
    event_number = str(alert_record.get("event_number") or "").strip()
    connectivity = str(connectivity_status or alert_record.get("connectivity_status") or "not_checked").strip()

    if event_number == "4720":
        category = "identity"
        base = "Usuário criado"
    elif event_number in {"4728", "4732", "4756"}:
        category = "identity_privilege"
        base = "Usuário adicionado a grupo privilegiado"
    elif event_number == "4625":
        category = "authentication"
        base = "Tentativa de login inválida"
    elif event_number == "9001":
        category = "service"
        base = "Serviço crítico parado"
    else:
        category = "generic"
        display_name = str(alert_record.get("display_name") or alert_record.get("event") or "Evento recebido").strip()
        base = display_name or "Evento recebido"

    if connectivity == "reachable":
        return f"{base} em host alcançável.", category
    if connectivity == "unreachable":
        return f"{base} em host não alcançável.", category
    if connectivity == "checking":
        return f"{base}; validação de conectividade em andamento.", category
    if connectivity == "check_failed":
        return f"{base}; validação de conectividade falhou.", category

    return f"{base}; conectividade ainda não validada.", category


def build_recommended_actions(alert_record: Dict[str, Any], connectivity_status: str | None = None) -> List[str]:
    """Gera sugestões operacionais iniciais para o analista.

    As sugestões não executam automação. Elas apenas orientam a triagem.
    A automação/playbook será tratada em etapa posterior, baseada em evento/regra.
    """
    event_number = str(alert_record.get("event_number") or "").strip()
    severity = _normalize_text(alert_record.get("severity"))
    connectivity = str(connectivity_status or alert_record.get("connectivity_status") or "not_checked").strip()

    actions: List[str] = []

    if event_number == "4720":
        actions.append("Revisar se a criação do usuário foi autorizada")
        actions.append("Validar privilégios e grupos atribuídos ao usuário")
        actions.append("Confirmar solicitante ou mudança vinculada ao processo interno")

    elif event_number in {"4728", "4732", "4756"}:
        actions.append("Validar se a inclusão em grupo privilegiado foi autorizada")
        actions.append("Revisar associação do usuário em grupos administrativos")
        actions.append("Verificar se há mudança aprovada para a elevação de privilégio")

    elif event_number == "4625":
        actions.append("Verificar volume e origem das tentativas de login inválidas")
        actions.append("Validar se o usuário está bloqueado ou sob tentativa de força bruta")

    elif event_number == "9001":
        actions.append("Validar impacto do serviço crítico parado")
        actions.append("Verificar se houve janela de manutenção ou parada autorizada")

    else:
        actions.append("Validar o evento com o responsável pelo ativo ou identidade")

    if connectivity == "reachable":
        actions.append("Host alcançável: verificar atividade recente no ativo")
    elif connectivity == "unreachable":
        actions.append("Host não alcançável: validar se o ativo está desligado, isolado ou fora da rede")
    elif connectivity == "not_checked":
        actions.append("Executar validação de conectividade pelo painel do alerta")

    if "crit" in severity or "alta" in severity or "high" in severity:
        actions.append("Priorizar triagem por severidade elevada")

    # Remove duplicados preservando ordem
    deduped: List[str] = []
    for item in actions:
        if item and item not in deduped:
            deduped.append(item)

    return deduped

def create_alert_from_inbound(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_if_needed(payload or {})
    alert_id = ensure_alert_id(normalized.get("alert_id"))
    normalized["alert_id"] = alert_id

    existing = get_alert_by_id(alert_id)
    if existing:
        return existing

    alert_record = build_alert_record(normalized)
    risk_score, risk_level = calculate_alert_risk(alert_record)
    context_summary, context_category = build_alert_context(alert_record, "not_checked")
    recommended_actions = build_recommended_actions(alert_record, "not_checked")

    alert_record["risk_score"] = risk_score
    alert_record["risk_level"] = risk_level
    alert_record["context_summary"] = context_summary
    alert_record["context_category"] = context_category
    alert_record["recommended_actions"] = recommended_actions

    alert = upsert_alert(alert_record)

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
