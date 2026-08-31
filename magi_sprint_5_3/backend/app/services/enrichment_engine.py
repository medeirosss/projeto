from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class FingerprintResult:
    asset_type: str
    confidence: int
    rule_id: str | None
    reasons: list[str]
    fingerprinted_at: datetime
    evidence: list[dict[str, Any]]
    internal_rule_id: str | None = None
    compliance_rule_id: int | None = None


_DEFAULT_RULES = Path(__file__).resolve().parents[2] / "config" / "fingerprints.yaml"
_ALLOWED_FIELDS = {"hostname", "dns_name", "vendor", "display_name"}
_ALLOWED_COMPLIANCE_TYPES = {"server", "workstation", "network_device"}

# Public and intentionally stable scoring model. The technician can define the
# naming compliance, while Magi owns the weights so a score keeps the same
# meaning across environments.
SCORING_CRITERIA = [
    {"key": "discovered", "label": "Ativo confirmado pelo Discovery", "points": 5, "kind": "positive"},
    {"key": "fingerprint", "label": "Regra interna de fingerprint compatível", "points": 45, "kind": "positive"},
    {"key": "vendor", "label": "Fabricante identificado pelo MAC/OUI", "points": 15, "kind": "positive"},
    {"key": "hostname", "label": "Hostname/DNS identificado", "points": 10, "kind": "positive"},
    {"key": "compliance_match", "label": "Nome atende à regra de compliance da classe", "points": 25, "kind": "positive"},
    {"key": "compliance_mismatch", "label": "Nome diverge da regra de compliance da classe", "points": -25, "kind": "negative"},
]


def scoring_policy() -> dict[str, Any]:
    return {
        "minimum": 0,
        "maximum": 100,
        "criteria": SCORING_CRITERIA,
        "bands": [
            {"min": 90, "max": 100, "label": "Alta confiança"},
            {"min": 70, "max": 89, "label": "Boa confiança"},
            {"min": 40, "max": 69, "label": "Confiança parcial"},
            {"min": 0, "max": 39, "label": "Baixa confiança"},
        ],
    }


def _values(asset: dict[str, Any], field: str) -> list[str]:
    value = asset.get(field)
    return [str(value).strip().lower()] if value not in (None, "") else []


def _match_condition(values: list[str], condition: dict[str, Any]) -> bool:
    if not values:
        return False
    for operator, expected in condition.items():
        terms = expected if isinstance(expected, list) else [expected]
        terms = [str(x).strip().lower() for x in terms if str(x).strip()]
        if not terms:
            continue
        if operator == "equals" and any(v == term for v in values for term in terms):
            return True
        if operator == "contains" and any(term in v for v in values for term in terms):
            return True
        if operator == "starts_with" and any(v.startswith(term) for v in values for term in terms):
            return True
        if operator == "ends_with" and any(v.endswith(term) for v in values for term in terms):
            return True
        if operator == "regex":
            for term in terms:
                try:
                    if any(re.search(term, v, re.IGNORECASE) for v in values):
                        return True
                except re.error:
                    continue
    return False


def _rule_matches(asset: dict[str, Any], match: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for field, condition in match.items():
        if field not in _ALLOWED_FIELDS or not isinstance(condition, dict):
            return False, []
        values = _values(asset, field)
        if not _match_condition(values, condition):
            return False, []
        reasons.append(f"{field}={values[0] if values else ''}")
    return True, reasons


def load_rules(path: Path | None = None) -> list[dict[str, Any]]:
    rules_path = path or _DEFAULT_RULES
    if not rules_path.exists():
        return []
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules") or []
    return [r for r in rules if isinstance(r, dict)]


def _hostname_value(asset: dict[str, Any]) -> str:
    return str(asset.get("hostname") or asset.get("dns_name") or asset.get("display_name") or "").strip().lower()


def compliance_configured(rule: dict[str, Any]) -> bool:
    return bool(rule and rule.get("enabled", True) and any(str(rule.get(k) or "").strip() for k in ("starts_with", "contains_text", "ends_with")))


def compliance_matches(asset: dict[str, Any], rule: dict[str, Any]) -> bool:
    if not compliance_configured(rule):
        return False
    value = _hostname_value(asset)
    if not value:
        return False
    configured = False
    start = str(rule.get("starts_with") or "").strip().lower()
    middle = str(rule.get("contains_text") or "").strip().lower()
    end = str(rule.get("ends_with") or "").strip().lower()
    if start:
        configured = True
        if not value.startswith(start):
            return False
    if middle:
        configured = True
        if middle not in value:
            return False
    if end:
        configured = True
        if not value.endswith(end):
            return False
    return configured


def _add_evidence(evidence: list[dict[str, Any]], key: str, detail: str, points: int, status: str = "matched") -> None:
    criterion = next((item for item in SCORING_CRITERIA if item["key"] == key), None)
    evidence.append({
        "key": key,
        "label": criterion["label"] if criterion else key,
        "detail": detail,
        "points": points,
        "status": status,
    })


def fingerprint_asset(
    asset: dict[str, Any],
    rules: list[dict[str, Any]] | None = None,
    compliance_rules: list[dict[str, Any]] | None = None,
) -> FingerprintResult:
    candidates: list[dict[str, Any]] = []
    for index, rule in enumerate(rules if rules is not None else load_rules()):
        matched, reasons = _rule_matches(asset, rule.get("match") or {})
        if not matched:
            continue
        candidates.append({
            "asset_type": str(rule.get("asset_type") or "unknown").strip().lower(),
            "priority": max(0, min(100, int(rule.get("confidence") or 0))),
            "rule_id": str(rule.get("id") or f"rule-{index+1}"),
            "reasons": reasons,
        })
    internal = sorted(candidates, key=lambda item: item["priority"], reverse=True)[0] if candidates else None
    final_type = internal["asset_type"] if internal else "unknown"

    compliance_rules = [r for r in (compliance_rules or []) if str(r.get("asset_type") or "").lower() in _ALLOWED_COMPLIANCE_TYPES]
    matching_compliance = [r for r in compliance_rules if compliance_matches(asset, r)]
    applicable = next((r for r in compliance_rules if str(r.get("asset_type") or "").lower() == final_type and compliance_configured(r)), None)

    # A naming rule may classify an otherwise unknown host, but it is deliberately
    # a medium-confidence signal until other evidence corroborates it.
    if final_type == "unknown" and matching_compliance:
        final_type = str(matching_compliance[0].get("asset_type") or "unknown").lower()
        applicable = matching_compliance[0]

    evidence: list[dict[str, Any]] = []
    score = 0
    score += 5
    _add_evidence(evidence, "discovered", f"IP {asset.get('ip_address') or ''} confirmado no scan", 5)

    if internal:
        score += 45
        _add_evidence(evidence, "fingerprint", f"Regra interna {internal['rule_id']} compatível", 45)

    if asset.get("vendor"):
        score += 15
        _add_evidence(evidence, "vendor", str(asset.get("vendor")), 15)

    if asset.get("hostname") or asset.get("dns_name"):
        score += 10
        _add_evidence(evidence, "hostname", str(asset.get("dns_name") or asset.get("hostname")), 10)

    compliance_rule_id = None
    if applicable:
        compliance_rule_id = int(applicable["id"]) if applicable.get("id") is not None else None
        if compliance_matches(asset, applicable):
            score += 25
            _add_evidence(evidence, "compliance_match", str(applicable.get("name") or final_type), 25)
        else:
            score -= 25
            _add_evidence(evidence, "compliance_mismatch", str(applicable.get("name") or final_type), -25, "mismatch")

    score = max(0, min(100, score))
    reasons = list(internal["reasons"] if internal else [])
    if applicable:
        reasons.append(f"compliance={applicable.get('name') or final_type}:{'match' if compliance_matches(asset, applicable) else 'mismatch'}")

    return FingerprintResult(
        asset_type=final_type,
        confidence=score,
        rule_id=internal["rule_id"] if internal else None,
        reasons=reasons,
        fingerprinted_at=datetime.utcnow(),
        evidence=evidence,
        internal_rule_id=internal["rule_id"] if internal else None,
        compliance_rule_id=compliance_rule_id,
    )
