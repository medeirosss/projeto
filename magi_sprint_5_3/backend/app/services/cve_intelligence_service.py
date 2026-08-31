from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_INTELLIGENCE_FILE = Path(__file__).resolve().parents[1] / "data" / "cve_intelligence.json"


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _normalize_cve(value: Any) -> str:
    text = _clean(value).upper()
    match = re.search(r"CVE-\d{4}-\d{4,}", text)
    return match.group(0) if match else text


def _to_float(value: Any) -> float:
    text = _clean(value).replace(",", ".")
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    try:
        return float(match.group(0))
    except Exception:
        return 0.0


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _clean(value).lower()
    if not text:
        return None
    positive = ("true", "yes", "sim", "available", "disponivel", "disponível", "exploit", "exploited", "existe", "1")
    negative = ("false", "no", "nao", "não", "unavailable", "indisponivel", "indisponível", "not available", "na", "0")
    if any(x in text for x in positive):
        return True
    if any(x in text for x in negative):
        return False
    return None


def _normalize_severity(value: Any) -> str:
    text = _clean(value).lower()
    if "crit" in text or text == "5":
        return "critical"
    if "high" in text or "alta" in text or text == "4":
        return "high"
    if "medium" in text or "media" in text or "média" in text or text == "3":
        return "medium"
    if "low" in text or "baixa" in text or text in {"1", "2"}:
        return "low"
    return text or "critical"


def _risk_label(score: int) -> str:
    if score >= 90:
        return "Critico"
    if score >= 70:
        return "Alto"
    if score >= 45:
        return "Medio"
    return "Baixo"


def _load_intelligence() -> Dict[str, Any]:
    path = Path(os.getenv("CVE_INTELLIGENCE_FILE") or DEFAULT_INTELLIGENCE_FILE)
    if not path.exists():
        return {"version": "empty", "default_policy": {}, "exact_cves": {}, "keyword_rules": [], "playbooks": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _joined_context(row: Dict[str, Any]) -> str:
    keys = (
        "id", "cve", "cve_id", "product", "platform", "name", "title", "description", "summary",
        "vulnerabilityname", "vulnerability_name", "software", "cvss_vector", "cvss3_vector"
    )
    return " ".join(_clean(row.get(k)) for k in keys if _clean(row.get(k))).lower()


def _extract_signals(row: Dict[str, Any]) -> Dict[str, Any]:
    severity = _normalize_severity(row.get("severity") or row.get("severity_name") or "critical")
    cvss = max(
        _to_float(row.get("cvss3") or row.get("cvss_3") or row.get("cvss_score") or row.get("cvss3_score")),
        _to_float(row.get("cvss2") or row.get("cvss_2")),
    )
    exploit_available = _to_bool(
        row.get("exploit_available")
        if row.get("exploit_available") is not None
        else row.get("exploit_status") or row.get("status_exploit") or row.get("exploited_cve_ids")
    )
    patch_available = _to_bool(
        row.get("patch_available")
        if row.get("patch_available") is not None
        else row.get("patch_status") or row.get("patch_availability") or row.get("availability_of_patch")
    )
    affected = int(_to_float(row.get("affected_systems") or row.get("affected_count") or row.get("systems_affected") or 0))
    if severity == "critical" and cvss == 0:
        cvss = 9.0
    return {
        "severity": severity,
        "cvss": cvss,
        "exploit_available": exploit_available,
        "patch_available": patch_available,
        "affected_systems": affected,
    }


def _choose_policy(signals: Dict[str, Any], db: Dict[str, Any]) -> str:
    severity = signals["severity"]
    cvss = float(signals["cvss"] or 0)
    exploit = signals["exploit_available"]
    patch = signals["patch_available"]

    if exploit is True and cvss >= 8.0:
        return "critical_with_exploit"
    if severity == "critical" and patch is False:
        return "critical_no_patch"
    if severity == "critical" and patch is True:
        return "critical_patch_available"
    if severity in {"critical", "high"} and patch is False:
        return "high_no_patch"
    return "patch_only"


def _policy_decision(policy_name: str, db: Dict[str, Any]) -> Dict[str, Any]:
    policy = (db.get("default_policy") or {}).get(policy_name) or (db.get("default_policy") or {}).get("patch_only") or {}
    return {
        "policy": policy_name,
        "magi_risk_score": int(policy.get("risk_score") or 55),
        "magi_risk_level": str(policy.get("risk_level") or "Medio"),
        "defense_playbook": str(policy.get("defense_playbook") or "monitor_until_patch"),
        "remediation_playbook": str(policy.get("remediation_playbook") or "schedule_patch"),
        "immediate_action": str(policy.get("immediate_action") or "Monitorar o ativo e validar exposição."),
        "remediation_action": str(policy.get("remediation_action") or "Aplicar correção conforme janela operacional."),
        "defense_actions": list(policy.get("defense_actions") or []),
    }


def _apply_exact_and_keyword_rules(row: Dict[str, Any], decision: Dict[str, Any], db: Dict[str, Any]) -> Dict[str, Any]:
    cve = decision["cve"]
    exact = (db.get("exact_cves") or {}).get(cve)
    tags: List[str] = []
    matched_rules: List[str] = []
    context = _joined_context(row)

    if exact:
        forced = exact.get("force_policy")
        if forced:
            decision.update(_policy_decision(str(forced), db))
        decision.update({
            "exploit_type": str(exact.get("exploit_type") or decision.get("exploit_type") or "Unknown"),
            "attack_vector": str(exact.get("attack_vector") or decision.get("attack_vector") or "unknown"),
            "requires_auth": exact.get("requires_auth"),
            "cve_name": exact.get("name") or "",
            "decision_reason": str(exact.get("decision_reason") or "CVE encontrado na base local de inteligência."),
            "confidence": "alta",
        })
        tags.extend(exact.get("tags") or [])
        matched_rules.append(f"exact:{cve}")

    for rule in db.get("keyword_rules") or []:
        keywords = [str(x).lower() for x in rule.get("keywords") or []]
        if not any(keyword and keyword in context for keyword in keywords):
            continue
        matched_rules.append(str(rule.get("name") or "keyword_rule"))
        decision["magi_risk_score"] = min(100, int(decision.get("magi_risk_score") or 0) + int(rule.get("risk_bonus") or 0))
        decision["magi_risk_level"] = _risk_label(int(decision["magi_risk_score"]))
        if decision.get("exploit_type") in ("", "Unknown", None):
            decision["exploit_type"] = str(rule.get("exploit_type") or "Unknown")
        if decision.get("attack_vector") in ("", "unknown", None):
            decision["attack_vector"] = str(rule.get("attack_vector") or "unknown")
        if decision.get("requires_auth") is None and rule.get("requires_auth") is not None:
            decision["requires_auth"] = rule.get("requires_auth")
        if rule.get("preferred_policy") and not exact:
            # Use the rule to shift from pure patching to defense-oriented playbooks.
            policy_decision = _policy_decision(str(rule.get("preferred_policy")), db)
            for key in ("defense_playbook", "immediate_action", "defense_actions"):
                decision[key] = policy_decision[key]
        tags.extend(rule.get("tags") or [])

    if matched_rules:
        decision["matched_rule"] = ", ".join(matched_rules)
        if decision.get("confidence") != "alta":
            decision["confidence"] = "media"
        if not decision.get("decision_reason"):
            decision["decision_reason"] = "Decisão baseada em sinais do scanner e padrões do produto/descrição."
    else:
        decision["matched_rule"] = decision.get("policy", "policy")
        decision["confidence"] = "baixa"
        decision["decision_reason"] = "Decisão baseada em CVSS, exploit disponível e disponibilidade de patch informados pela fonte."

    decision["tags"] = list(dict.fromkeys(tags or ["scanner-signal"]))
    return decision


def analyze_cve(row: Dict[str, Any]) -> Dict[str, Any]:
    db = _load_intelligence()
    cve = _normalize_cve(row.get("id") or row.get("cve") or row.get("cve_id"))
    signals = _extract_signals(row)
    policy_name = _choose_policy(signals, db)
    decision = _policy_decision(policy_name, db)

    decision.update({
        "cve": cve,
        "source": "magi_cve_engine_v1.1",
        "engine_version": db.get("version") or "1.1",
        "severity_source": signals["severity"],
        "cvss_score": signals["cvss"],
        "exploit_available": signals["exploit_available"],
        "patch_available": signals["patch_available"],
        "affected_systems": signals["affected_systems"],
        "exploit_type": "Unknown",
        "attack_vector": "unknown",
        "requires_auth": None,
    })
    decision = _apply_exact_and_keyword_rules(row, decision, db)

    # Extra escalation: exploit + many affected systems should not look like ordinary patching.
    if decision.get("exploit_available") is True and int(decision.get("affected_systems") or 0) >= 10:
        decision["magi_risk_score"] = min(100, max(int(decision["magi_risk_score"]), 95))
        decision["magi_risk_level"] = _risk_label(int(decision["magi_risk_score"]))
        if "prioritize_mass_response" not in decision["defense_actions"]:
            decision["defense_actions"].append("prioritize_mass_response")

    return decision


def enrich_cve_row(row: Dict[str, Any]) -> Dict[str, Any]:
    decision = analyze_cve(row)
    enriched = dict(row)
    enriched["cve_intelligence"] = decision
    enriched["magi_risk_score"] = decision.get("magi_risk_score")
    enriched["magi_risk_level"] = decision.get("magi_risk_level")
    enriched["exploit_type"] = decision.get("exploit_type")
    enriched["attack_vector"] = decision.get("attack_vector")
    enriched["defense_playbook"] = decision.get("defense_playbook")
    enriched["remediation_playbook"] = decision.get("remediation_playbook")
    enriched["immediate_action"] = decision.get("immediate_action")
    enriched["remediation_action"] = decision.get("remediation_action")
    enriched["defense_actions"] = decision.get("defense_actions")
    enriched["decision_reason"] = decision.get("decision_reason")
    # Backward compatibility with v1 UI/code.
    enriched["recommended_playbook"] = decision.get("defense_playbook")
    enriched["recommended_action"] = decision.get("immediate_action")
    return enriched


def enrich_cve_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_cve_row(row) for row in rows]


def list_rules() -> Dict[str, Any]:
    db = _load_intelligence()
    return {
        "version": db.get("version"),
        "exact_cves": sorted((db.get("exact_cves") or {}).keys()),
        "keyword_rules": [rule.get("name") for rule in db.get("keyword_rules") or []],
        "playbooks": db.get("playbooks") or {},
        "default_policy": db.get("default_policy") or {},
    }
