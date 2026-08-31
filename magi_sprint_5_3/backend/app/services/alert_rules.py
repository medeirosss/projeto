from __future__ import annotations

from typing import Any, Dict, List


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _event_number(alert: Dict[str, Any]) -> str:
    return str(alert.get("event_number") or "").strip()


def _connectivity(connectivity_status: str | None, alert: Dict[str, Any]) -> str:
    return str(connectivity_status or alert.get("connectivity_status") or "not_checked").strip()


def _has_ip(alert: Dict[str, Any]) -> bool:
    return bool(alert.get("ip_address") or alert.get("target_ip") or alert.get("source_ip"))


def _base_severity_score(severity: Any) -> int:
    sev = _normalize_text(severity)
    if "crit" in sev:
        return 50
    if "alta" in sev or "high" in sev:
        return 40
    if "media" in sev or "média" in sev or "medium" in sev:
        return 20
    if "baixa" in sev or "low" in sev:
        return 10
    return 0


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


ALERT_RULES: List[Dict[str, Any]] = [
    {
        "rule_key": "ad_user_created",
        "event_numbers": {"4720"},
        "category": "identity",
        "risk_boost": 30,
        "context": {
            "reachable": "Usuário criado em host alcançável.",
            "unreachable": "Usuário criado em host não alcançável.",
            "checking": "Usuário criado; validação de conectividade em andamento.",
            "check_failed": "Usuário criado; validação de conectividade falhou.",
            "not_checked": "Usuário criado; conectividade ainda não validada.",
        },
        "actions": [
            "Revisar se a criação do usuário foi autorizada",
            "Validar privilégios e grupos atribuídos ao usuário",
            "Confirmar solicitante ou mudança vinculada ao processo interno",
        ],
        "suggested_playbooks": ["ad_user_review", "ad_group_membership_check"],
    },
    {
        "rule_key": "ad_privileged_group_membership_added",
        "event_numbers": {"4728", "4732", "4756"},
        "category": "identity_privilege",
        "risk_boost": 40,
        "context": {
            "reachable": "Usuário adicionado a grupo privilegiado em host alcançável.",
            "unreachable": "Usuário adicionado a grupo privilegiado em host não alcançável.",
            "checking": "Usuário adicionado a grupo privilegiado; validação de conectividade em andamento.",
            "check_failed": "Usuário adicionado a grupo privilegiado; validação de conectividade falhou.",
            "not_checked": "Usuário adicionado a grupo privilegiado; conectividade ainda não validada.",
        },
        "actions": [
            "Validar se a inclusão em grupo privilegiado foi autorizada",
            "Revisar associação do usuário em grupos administrativos",
            "Verificar se há mudança aprovada para a elevação de privilégio",
        ],
        "suggested_playbooks": ["ad_privileged_group_review", "ad_user_session_check"],
    },
    {
        "rule_key": "failed_logon",
        "event_numbers": {"4625"},
        "category": "authentication",
        "risk_boost": 20,
        "context": {
            "reachable": "Tentativa de login inválida em host alcançável.",
            "unreachable": "Tentativa de login inválida em host não alcançável.",
            "checking": "Tentativa de login inválida; validação de conectividade em andamento.",
            "check_failed": "Tentativa de login inválida; validação de conectividade falhou.",
            "not_checked": "Tentativa de login inválida; conectividade ainda não validada.",
        },
        "actions": [
            "Verificar volume e origem das tentativas de login inválidas",
            "Validar se o usuário está bloqueado ou sob tentativa de força bruta",
            "Correlacionar com eventos recentes do mesmo usuário e IP",
        ],
        "suggested_playbooks": ["failed_logon_correlation"],
    },
    {
        "rule_key": "critical_service_stopped",
        "event_numbers": {"9001"},
        "category": "service",
        "risk_boost": 30,
        "context": {
            "reachable": "Serviço crítico parado em host alcançável.",
            "unreachable": "Serviço crítico parado em host não alcançável.",
            "checking": "Serviço crítico parado; validação de conectividade em andamento.",
            "check_failed": "Serviço crítico parado; validação de conectividade falhou.",
            "not_checked": "Serviço crítico parado; conectividade ainda não validada.",
        },
        "actions": [
            "Validar impacto do serviço crítico parado",
            "Verificar se houve janela de manutenção ou parada autorizada",
            "Avaliar reinício controlado do serviço após validação operacional",
        ],
        "suggested_playbooks": ["service_status_check", "service_restart_manual_approval"],
    },
]


def _match_rules(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    event_number = _event_number(alert)
    return [rule for rule in ALERT_RULES if event_number in rule.get("event_numbers", set())]


def _dedupe(items: List[str]) -> List[str]:
    result: List[str] = []
    for item in items:
        if item and item not in result:
            result.append(item)
    return result


def _generic_context(alert: Dict[str, Any], connectivity: str) -> tuple[str, str]:
    display_name = str(alert.get("display_name") or alert.get("event") or "Evento recebido").strip()
    base = display_name or "Evento recebido"

    if connectivity == "reachable":
        return f"{base} em host alcançável.", "generic"
    if connectivity == "unreachable":
        return f"{base} em host não alcançável.", "generic"
    if connectivity == "checking":
        return f"{base}; validação de conectividade em andamento.", "generic"
    if connectivity == "check_failed":
        return f"{base}; validação de conectividade falhou.", "generic"
    return f"{base}; conectividade ainda não validada.", "generic"


def evaluate_alert_rules(alert: Dict[str, Any], connectivity_status: str | None = None) -> Dict[str, Any]:
    """Motor hardcoded inicial de regras do Magi.

    Esta função centraliza risco, contexto e ações recomendadas sem criar tabela ainda.
    Depois, a mesma estrutura pode migrar para banco como alert_rules.
    """
    connectivity = _connectivity(connectivity_status, alert)
    matched_rules = _match_rules(alert)

    score = _base_severity_score(alert.get("severity"))
    if _has_ip(alert):
        score += 10
    if alert.get("mitre_technique") or alert.get("technique"):
        score += 10

    actions: List[str] = []
    suggested_playbooks: List[str] = []
    context_summary = ""
    context_category = "generic"
    matched_rule_keys: List[str] = []

    for rule in matched_rules:
        matched_rule_keys.append(str(rule.get("rule_key") or ""))
        score += int(rule.get("risk_boost") or 0)
        context_category = str(rule.get("category") or context_category)
        if not context_summary:
            context_summary = str((rule.get("context") or {}).get(connectivity) or "")
        actions.extend(rule.get("actions") or [])
        suggested_playbooks.extend(rule.get("suggested_playbooks") or [])

    if not context_summary:
        context_summary, context_category = _generic_context(alert, connectivity)

    if connectivity == "reachable":
        actions.append("Host alcançável: verificar atividade recente no ativo")
    elif connectivity == "unreachable":
        actions.append("Host não alcançável: validar se o ativo está desligado, isolado ou fora da rede")
    elif connectivity == "not_checked":
        actions.append("Executar validação de conectividade pelo painel do alerta")

    severity = _normalize_text(alert.get("severity"))
    if "crit" in severity or "alta" in severity or "high" in severity:
        actions.append("Priorizar triagem por severidade elevada")

    score = max(0, min(int(score), 100))

    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "context_summary": context_summary,
        "context_category": context_category,
        "recommended_actions": _dedupe(actions),
        "suggested_playbooks": _dedupe(suggested_playbooks),
        "matched_rules": [key for key in matched_rule_keys if key],
    }
