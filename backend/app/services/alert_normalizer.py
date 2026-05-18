from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable


EVENT_MAP: Dict[str, Dict[str, str]] = {
    "4624": {
        "display_name": "Logon realizado com sucesso",
        "severity": "Baixa",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1078",
        "nist_control": "AU-2",
        "recommendation": "Validar se o logon faz parte do comportamento esperado do usuário e do host.",
    },
    "4625": {
        "display_name": "Falha de login",
        "severity": "Alta",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "AC-7",
        "recommendation": "Verificar tentativa de brute force, senha incorreta recorrente ou origem não reconhecida.",
    },
    "4648": {
        "display_name": "Logon com credenciais explícitas",
        "severity": "Media",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1550",
        "nist_control": "IA-2",
        "recommendation": "Validar se o uso de credenciais explícitas é esperado para o processo e usuário informado.",
    },
    "4672": {
        "display_name": "Privilégios especiais atribuídos ao logon",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078",
        "nist_control": "AC-6",
        "recommendation": "Confirmar se o usuário deveria receber privilégios administrativos no logon.",
    },
    "4688": {
        "display_name": "Processo criado",
        "severity": "Media",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "nist_control": "AU-12",
        "recommendation": "Validar processo, linha de comando e usuário executor quando disponível.",
    },
    "4719": {
        "display_name": "Política de auditoria alterada",
        "severity": "Alta",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.002",
        "nist_control": "AU-6",
        "recommendation": "Verificar se a alteração da política de auditoria foi autorizada.",
    },
    "4720": {
        "display_name": "Conta de usuário criada",
        "severity": "Alta",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.002",
        "nist_control": "AC-2",
        "recommendation": "Confirmar se a criação da conta foi aprovada e se o usuário criado possui permissões adequadas.",
    },
    "4722": {
        "display_name": "Conta de usuário habilitada",
        "severity": "Media",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
        "recommendation": "Validar se a reativação da conta foi autorizada.",
    },
    "4723": {
        "display_name": "Tentativa de alteração de senha",
        "severity": "Media",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "IA-5",
        "recommendation": "Validar se a alteração de senha foi solicitada pelo usuário legítimo.",
    },
    "4724": {
        "display_name": "Tentativa de reset de senha",
        "severity": "Alta",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1098",
        "nist_control": "IA-5",
        "recommendation": "Confirmar se o reset de senha foi autorizado pelo processo de suporte/gestão.",
    },
    "4725": {
        "display_name": "Conta de usuário desabilitada",
        "severity": "Media",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
        "nist_control": "AC-2",
        "recommendation": "Validar se a desativação da conta faz parte de um processo autorizado.",
    },
    "4726": {
        "display_name": "Conta de usuário removida",
        "severity": "Alta",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
        "nist_control": "AC-2",
        "recommendation": "Confirmar se a exclusão da conta foi aprovada e registrar evidência da solicitação.",
    },
    "4728": {
        "display_name": "Membro adicionado a grupo global de segurança",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
        "recommendation": "Validar se a inclusão no grupo foi aprovada. Se for grupo privilegiado, tratar como crítico.",
    },
    "4732": {
        "display_name": "Membro adicionado a grupo local de segurança",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
        "recommendation": "Validar se a inclusão no grupo local foi aprovada. Se for Administrators, tratar como crítico.",
    },
    "4738": {
        "display_name": "Conta de usuário alterada",
        "severity": "Media",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
        "recommendation": "Revisar quais atributos da conta foram alterados e se a alteração foi autorizada.",
    },
    "4740": {
        "display_name": "Conta de usuário bloqueada",
        "severity": "Media",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "AC-7",
        "recommendation": "Verificar origem do bloqueio e recorrência para identificar tentativa de autenticação indevida.",
    },
    "4756": {
        "display_name": "Membro adicionado a grupo universal de segurança",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
        "recommendation": "Validar a inclusão no grupo e revisar escopo de permissões concedidas.",
    },
    "1102": {
        "display_name": "Log de auditoria limpo",
        "severity": "Critica",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001",
        "nist_control": "AU-6",
        "recommendation": "Investigar imediatamente quem limpou o log e preservar evidências disponíveis.",
    },
    "7045": {
        "display_name": "Serviço instalado",
        "severity": "Alta",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1543.003",
        "nist_control": "CM-7",
        "recommendation": "Validar serviço instalado, binário, usuário executor e origem da instalação.",
    },
}

PRIVILEGED_GROUP_KEYWORDS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "administradores",
    "account operators",
    "backup operators",
)

NOISE_VALUES = {"", "none", "null", "undefined", "-", "n/a", "na", "not available"}


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    text = str(value).strip().strip('"').strip("'")
    if text.lower() in NOISE_VALUES:
        return ""
    return text


def _get(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        current: Any = payload
        ok = True
        for part in key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                ok = False
                break
        if ok:
            value = _clean(current)
            if value:
                return value
    return ""


def _extract_event_id(payload: Dict[str, Any]) -> str:
    raw = _get(
        payload,
        "event_number",
        "event_id",
        "eventId",
        "EventID",
        "event.code",
        "winlog.event_id",
        "windows.event_id",
        "rule.id",
        "event_identifier",
    )
    match = re.search(r"\b(\d{4,5})\b", raw)
    return match.group(1) if match else raw


def _detect_source(payload: Dict[str, Any]) -> str:
    explicit = _get(payload, "source_system", "source", "vendor", "product", "observer.vendor")
    if explicit:
        return explicit
    if _get(payload, "event_type_text", "caller_user_sid", "ACCOUNT_NAME", "account_name") or _extract_event_id(payload):
        return "ADAuditPlus"
    if _get(payload, "rule.name", "agent.name", "winlog.channel"):
        return "SIEM"
    return "GenericWebhook"


def _normalize_severity(value: str, event_id: str, payload: Dict[str, Any]) -> str:
    raw = _clean(value).lower()
    group = _get(payload, "group_name", "target_group", "TargetGroupName", "group", "MemberOf", "memberof")
    group_l = group.lower()

    if any(keyword in group_l for keyword in PRIVILEGED_GROUP_KEYWORDS) and event_id in {"4728", "4732", "4756"}:
        return "Critica"

    aliases = {
        "critical": "Critica",
        "critica": "Critica",
        "crítica": "Critica",
        "high": "Alta",
        "alta": "Alta",
        "medium": "Media",
        "média": "Media",
        "media": "Media",
        "low": "Baixa",
        "baixa": "Baixa",
        "info": "Informativa",
        "informational": "Informativa",
        "success": "Baixa",
        "failure": "Alta",
        "failed": "Alta",
    }
    if raw in aliases:
        return aliases[raw]

    return EVENT_MAP.get(event_id, {}).get("severity", "Media")


def _dedupe_hash(values: Iterable[str]) -> str:
    joined = "|".join(_clean(v).lower() for v in values if _clean(v))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16] if joined else ""


def _build_alert_id(source_system: str, event_id: str, target_user: str, hostname: str, source_ip: str, timestamp: str) -> str:
    dedupe = _dedupe_hash([source_system, event_id, target_user, hostname, source_ip, timestamp[:16]])
    return f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{dedupe[:8].upper()}" if dedupe else ""


def normalize_inbound_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = payload or {}

    event_id = _extract_event_id(payload)
    mapped = EVENT_MAP.get(event_id, {})
    source_system = _detect_source(payload)

    target_user = _get(
        payload,
        "target_user",
        "target_username",
        "account_name",
        "ACCOUNT_NAME",
        "TargetUserName",
        "target.user.name",
        "user.name",
        "username",
        "user",
        "user_display_name",
        "Target Account",
    )

    actor_user = _get(
        payload,
        "actor_user",
        "caller_user_name",
        "CALLER_USER_NAME",
        "caller_user_sid",
        "SubjectUserName",
        "subject_user",
        "initiator",
        "actor",
        "subject.user.name",
        "winlog.event_data.SubjectUserName",
    )

    hostname = _get(
        payload,
        "hostname",
        "host_name",
        "machine",
        "computer",
        "host",
        "agent.name",
        "winlog.computer_name",
        "ComputerName",
    )

    source_ip = _get(
        payload,
        "source_ip",
        "src_ip",
        "client_ip",
        "ip",
        "IP",
        "source.ip",
        "host.ip",
        "IpAddress",
        "Source Network Address",
        "winlog.event_data.IpAddress",
    )

    target_ip = _get(payload, "target_ip", "dst_ip", "destination.ip", "server_ip") or source_ip
    group_name = _get(payload, "group_name", "target_group", "TargetGroupName", "group", "MemberOf", "memberof")

    timestamp = _get(payload, "timestamp", "date", "time", "event_time", "@timestamp") or datetime.now().isoformat()
    event_type = _get(payload, "event_type", "event.type", "winlog.channel")
    event_type_text = _get(payload, "event_type_text", "status", "outcome", "event.outcome")

    display_name = (
        mapped.get("display_name")
        or _get(payload, "display_name", "event_name", "event.action", "rule.name", "message")
        or (f"Evento {event_id}" if event_id else "Alerta inbound")
    )

    technique = _get(payload, "technique", "mitre_technique", "mitre_id", "rule.mitre.id") or mapped.get("mitre_technique", "")
    tactic = _get(payload, "tactic", "mitre_tactic", "rule.mitre.tactic") or mapped.get("mitre_tactic", "")
    nist = _get(payload, "nist", "nist_control") or mapped.get("nist_control", "")
    severity = _normalize_severity(_get(payload, "severity", "severity_text", "rule.level", "event_type_text"), event_id, payload)
    recommendation = _get(payload, "recommendation", "recommended_action") or mapped.get("recommendation", "Validar o evento com o time responsável e verificar se a atividade foi autorizada.")

    provided_alert_id = _get(payload, "alert_id", "alert_uuid", "id", "event.uuid")
    alert_id = provided_alert_id or _build_alert_id(source_system, event_id, target_user, hostname, source_ip, timestamp)

    normalized_context = {
        "actor_user": actor_user,
        "target_user": target_user,
        "group_name": group_name,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "hostname": hostname,
        "dedupe_key": _dedupe_hash([source_system, event_id, target_user, actor_user, hostname, source_ip, group_name, timestamp[:16]]),
        "recommendation": recommendation,
    }

    return {
        "alert_id": alert_id,
        "date": timestamp,
        "received_at": timestamp,
        "event": display_name,
        "event_number": event_id,
        "event_type": event_type,
        "event_type_text": event_type_text,
        "display_name": display_name,
        "username": target_user,
        "target_user": target_user,
        "actor_user": actor_user,
        "group_name": group_name,
        "technique": technique,
        "tactic": tactic,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "nist": nist,
        "nist_control": nist,
        "severity": severity,
        "source_system": source_system,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "ip_address": target_ip or source_ip,
        "hostname": hostname,
        "recommendation": recommendation,
        "normalized_context": normalized_context,
        "raw_payload": payload,
    }
