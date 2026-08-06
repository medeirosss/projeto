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


_DEFAULT_RULES = Path(__file__).resolve().parents[2] / "config" / "fingerprints.yaml"
_ALLOWED_FIELDS = {"hostname", "dns_name", "vendor", "display_name"}


def _values(asset: dict[str, Any], field: str) -> list[str]:
    value = asset.get(field)
    return [str(value).strip().lower()] if value not in (None, "") else []


def _match_condition(values: list[str], condition: dict[str, Any]) -> bool:
    if not values:
        return False
    for operator, expected in condition.items():
        terms = expected if isinstance(expected, list) else [expected]
        terms = [str(x).strip().lower() for x in terms if str(x).strip()]
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


def fingerprint_asset(asset: dict[str, Any], rules: list[dict[str, Any]] | None = None) -> FingerprintResult:
    candidates: list[FingerprintResult] = []
    for index, rule in enumerate(rules if rules is not None else load_rules()):
        matched, reasons = _rule_matches(asset, rule.get("match") or {})
        if not matched:
            continue
        confidence = max(0, min(100, int(rule.get("confidence") or 0)))
        candidates.append(FingerprintResult(
            asset_type=str(rule.get("asset_type") or "unknown").strip().lower(),
            confidence=confidence,
            rule_id=str(rule.get("id") or f"rule-{index+1}"),
            reasons=reasons,
            fingerprinted_at=datetime.utcnow(),
        ))
    if not candidates:
        return FingerprintResult("unknown", 0, None, [], datetime.utcnow())
    return sorted(candidates, key=lambda item: item.confidence, reverse=True)[0]
