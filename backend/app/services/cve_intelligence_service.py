from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


def _risk_level(score: int) -> str:
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
        return {"exact_cves": {}, "keyword_rules": [], "default_actions": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _base_decision(severity: str, db: Dict[str, Any]) -> Dict[str, Any]:
    defaults = db.get("default_actions") or {}
    item = defaults.get(severity) or defaults.get("critical") or {}
    return {
        "magi_risk_score": int(item.get("risk_score") or 70),
        "magi_risk_level": str(item.get("risk_level") or "Alto"),
        "recommended_playbook": str(item.get("recommended_playbook") or "patch_urgent"),
        "recommended_action": str(item.get("recommended_action") or "Aplicar patch e validar exposicao do ativo."),
        "decision_reason": "Decisao baseada na severidade informada pela fonte de vulnerabilidade.",
        "exploit_type": "Unknown",
        "attack_vector": "unknown",
        "requires_auth": None,
        "matched_rule": "default_severity",
        "confidence": "baixa",
        "tags": ["severity-based"],
    }


def _joined_context(row: Dict[str, Any]) -> str:
    keys = (
        "id", "cve", "cve_id", "product", "platform", "name", "title",
        "description", "summary", "vulnerabilityname", "vulnerability_name", "software"
    )
    return " ".join(_clean(row.get(k)) for k in keys if _clean(row.get(k))).lower()


def analyze_cve(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return Magi decision data for one CVE row.

    This is intentionally not a full CVE database. It is a decision engine:
    it enriches CVEs received from scanners with operational guidance.
    """
    db = _load_intelligence()
    cve = _normalize_cve(row.get("id") or row.get("cve") or row.get("cve_id"))
    severity = _normalize_severity(row.get("severity") or "critical")
    decision = _base_decision(severity, db)

    exact = (db.get("exact_cves") or {}).get(cve)
    if exact:
        score = int(exact.get("risk_score") or decision["magi_risk_score"])
        decision.update({
            "magi_risk_score": score,
            "magi_risk_level": str(exact.get("risk_level") or _risk_level(score)),
            "recommended_playbook": str(exact.get("recommended_playbook") or decision["recommended_playbook"]),
            "recommended_action": str(exact.get("recommended_action") or decision["recommended_action"]),
            "decision_reason": str(exact.get("decision_reason") or "CVE encontrado na base local de inteligencia."),
            "exploit_type": str(exact.get("exploit_type") or decision["exploit_type"]),
            "attack_vector": str(exact.get("attack_vector") or decision["attack_vector"]),
            "requires_auth": exact.get("requires_auth"),
            "matched_rule": f"exact:{cve}",
            "confidence": "alta",
            "tags": list(dict.fromkeys((decision.get("tags") or []) + (exact.get("tags") or []))),
            "cve_name": exact.get("name") or "",
        })
    else:
        context = _joined_context(row)
        matched_rules: List[str] = []
        tags: List[str] = list(decision.get("tags") or [])
        for rule in db.get("keyword_rules") or []:
            keywords = [str(x).lower() for x in rule.get("keywords") or []]
            if not any(keyword and keyword in context for keyword in keywords):
                continue
            matched_rules.append(str(rule.get("name") or "keyword_rule"))
            decision["magi_risk_score"] = min(100, int(decision["magi_risk_score"]) + int(rule.get("risk_delta") or 0))
            decision["magi_risk_level"] = _risk_level(int(decision["magi_risk_score"]))
            decision["recommended_playbook"] = str(rule.get("recommended_playbook") or decision["recommended_playbook"])
            decision["recommended_action"] = str(rule.get("recommended_action") or decision["recommended_action"])
            decision["exploit_type"] = str(rule.get("exploit_type") or decision["exploit_type"])
            decision["attack_vector"] = str(rule.get("attack_vector") or decision["attack_vector"])
            if rule.get("requires_auth") is not None:
                decision["requires_auth"] = rule.get("requires_auth")
            tags.extend(rule.get("tags") or [])

        if matched_rules:
            decision["matched_rule"] = ", ".join(matched_rules)
            decision["decision_reason"] = "Decisao baseada em padrao do produto/descricao associado ao CVE."
            decision["confidence"] = "media"
            decision["tags"] = list(dict.fromkeys(tags))

    decision["cve"] = cve
    decision["source"] = "magi_cve_engine_v1"
    return decision


def enrich_cve_row(row: Dict[str, Any]) -> Dict[str, Any]:
    decision = analyze_cve(row)
    enriched = dict(row)
    enriched["cve_intelligence"] = decision
    enriched["magi_risk_score"] = decision.get("magi_risk_score")
    enriched["magi_risk_level"] = decision.get("magi_risk_level")
    enriched["recommended_action"] = decision.get("recommended_action")
    enriched["recommended_playbook"] = decision.get("recommended_playbook")
    enriched["exploit_type"] = decision.get("exploit_type")
    enriched["attack_vector"] = decision.get("attack_vector")
    enriched["decision_reason"] = decision.get("decision_reason")
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
    }
