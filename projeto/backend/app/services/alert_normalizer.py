from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from app.services.alert_service import ensure_alert_id


EVENT_MAP: Dict[str, Dict[str, str]] = {
    "4624": {
        "display_name": "Successful Logon",
        "severity": "Baixa",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1078",
        "nist_control": "AU-2",
    },
    "4625": {
        "display_name": "Failed Logon",
        "severity": "Media",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "AU-2",
    },
    "4648": {
        "display_name": "Logon Using Explicit Credentials",
        "severity": "Media",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1550",
        "nist_control": "IA-2",
    },
    "4672": {
        "display_name": "Special Privileges Assigned to New Logon",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078",
        "nist_control": "AC-6",
    },
    "4688": {
        "display_name": "Process Created",
        "severity": "Media",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "nist_control": "AU-12",
    },
    "4719": {
        "display_name": "System Audit Policy Changed",
        "severity": "Alta",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.002",
        "nist_control": "AU-6",
    },
    "4720": {
        "display_name": "User Account Created",
        "severity": "Alta",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.002",
        "nist_control": "AC-2",
    },
    "4722": {
        "display_name": "User Account Enabled",
        "severity": "Media",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
    },
    "4723": {
        "display_name": "Attempt to Change Account Password",
        "severity": "Media",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "IA-5",
    },
    "4724": {
        "display_name": "Attempt to Reset Account Password",
        "severity": "Alta",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1098",
        "nist_control": "IA-5",
    },
    "4725": {
        "display_name": "User Account Disabled",
        "severity": "Media",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
        "nist_control": "AC-2",
    },
    "4726": {
        "display_name": "User Account Deleted",
        "severity": "Alta",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
        "nist_control": "AC-2",
    },
    "4728": {
        "display_name": "Member Added to Global Security Group",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
    },
    "4732": {
        "display_name": "Member Added to Local Security Group",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
    },
    "4738": {
        "display_name": "User Account Changed",
        "severity": "Media",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
    },
    "4740": {
        "display_name": "User Account Locked Out",
        "severity": "Media",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "nist_control": "AC-7",
    },
    "4756": {
        "display_name": "Member Added to Universal Security Group",
        "severity": "Alta",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "nist_control": "AC-2",
    },
    "1102": {
        "display_name": "Audit Log Cleared",
        "severity": "Critica",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001",
        "nist_control": "AU-6",
    },
    "7045": {
        "display_name": "Service Installed",
        "severity": "Alta",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1543.003",
        "nist_control": "CM-7",
    },
}

PRIVILEGED_GROUP_KEYWORDS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
)


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    text = str(value).strip()
    if text.lower() in {"none", "null", "undefined", "-", "n/a"}:
        return ""
    return text


def _get(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        if "." in key:
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
            continue
        if key in payload:
            value = _clean(payload.get(key))
            if value:
                return value
    return ""


def _extract_event_id(payload: Dict[str, Any]) -> str:
    event_id = _get(
        payload,
        "event_number",
        "event_id",
        "eventId",
        "EventID",
        "event.code",
        "winlog.event_id",
        "windows.event_id",
        "rule.id",
    )
    match = re.search(r"\b(\d{4,5})\b", event_id)
    return match.group(1) if match else event_id


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
    raw = value.strip().lower()
    group = _get(payload, "group_name", "target_group", "TargetGroupName", "group")
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
    }
    if raw in aliases:
        return aliases[raw]
    return EVENT_MAP.get(event_id, {}).get("severity", value or "Media")


def _dedupe_hash(values: Iterable[str]) -> str:
    joined = "|".join(_clean(v).lower() for v in values if _clean(v))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16] if joined else ""


def normalize_inbound_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = payload or {}
    event_id = _extract_event_id(payload)
    mapped = EVENT_MAP.get(event_id, {})
    source_system = _detect_source(payload)

    display_name = _get(payload, "display_name", "event_name", "event.action", "rule.name") or mapped.get("display_name", "Inbound Alert")
    event_type = _get(payload, "event_type", "event.type", "winlog.channel")
    event_type_text = _get(payload, "event_type_text", "status", "outcome", "event.outcome")

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
    )
    hostname = _get(payload, "hostname", "host_name", "machine", "computer", "host", "agent.name", "winlog.computer_name")
    source_ip = _get(payload, "source_ip", "src_ip", "client_ip", "ip", "IP", "source.ip", "host.ip")
    target_ip = _get(payload, "target_ip", "dst_ip", "destination.ip", "server_ip") or source_ip
    group_name = _get(payload, "group_name", "target_group", "TargetGroupName", "group")

    timestamp = _get(payload, "timestamp", "date", "time", "event_time", "@timestamp") or datetime.now().isoformat()
    technique = _get(payload, "technique", "mitre_technique", "mitre_id", "rule.mitre.id") or mapped.get("mitre_technique", "")
    tactic = _get(payload, "tactic", "mitre_tactic", "rule.mitre.tactic") or mapped.get("mitre_tactic", "")
    nist = _get(payload, "nist", "nist_control") or mapped.get("nist_control", "")
    severity = _normalize_severity(_get(payload, "severity", "severity_text", "rule.level"), event_id, payload)

    provided_alert_id = _get(payload, "alert_id", "alert_uuid", "id", "event.uuid")
    dedupe_key = _dedupe_hash([source_system, event_id, target_user, actor_user, hostname, source_ip, group_name, timestamp[:16]])

    normalized_context = {
        "actor_user": actor_user,
        "target_user": target_user,
        "group_name": group_name,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "hostname": hostname,
        "dedupe_key": dedupe_key,
    }

    return {
        "alert_id": ensure_alert_id(provided_alert_id),
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
        "nist": nist,
        "severity": severity,
        "source_system": source_system,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "ip_address": target_ip or source_ip,
        "hostname": hostname,
        "normalized_context": normalized_context,
        "raw_payload": payload,
    }
