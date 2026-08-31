from __future__ import annotations

import hmac
import ipaddress
from typing import Any, Dict, Iterable, Tuple

from fastapi import HTTPException, Request

from app.services.settings_service import get_settings_data

WEBHOOK_TOKEN_HEADER = "X-Centric-Webhook-Token"


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [line.strip() for line in value.replace(',', '\n').splitlines() if line.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _ip_in_sources(ip_value: str, sources: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(str(ip_value).strip())
    except Exception:
        return False

    for source in sources:
        source = str(source).strip()
        if not source:
            continue
        try:
            if '/' in source:
                if ip_obj in ipaddress.ip_network(source, strict=False):
                    return True
            else:
                if ip_obj == ipaddress.ip_address(source):
                    return True
        except Exception:
            # Ignore invalid entries instead of breaking inbound alert processing.
            continue
    return False


def _extract_direct_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _extract_real_ip(request: Request, webhook_settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Return the trusted real client IP.

    Proxy headers are only trusted when the direct peer IP is in webhook.trusted_proxies.
    This avoids accepting spoofed X-Forwarded-For/X-Real-IP headers from arbitrary clients.
    """
    direct_ip = _extract_direct_ip(request)
    proxy_enabled = bool(webhook_settings.get("proxy_enabled", False))
    trusted_proxies = _as_list(webhook_settings.get("trusted_proxies"))
    header_name = str(webhook_settings.get("real_ip_header") or "X-Forwarded-For").strip()

    debug = {
        "direct_ip": direct_ip,
        "proxy_enabled": proxy_enabled,
        "trusted_proxy": False,
        "real_ip_header": header_name,
        "header_value": None,
    }

    if not proxy_enabled:
        return direct_ip, debug

    if not _ip_in_sources(direct_ip, trusted_proxies):
        return direct_ip, debug

    debug["trusted_proxy"] = True
    header_value = request.headers.get(header_name) or ""
    debug["header_value"] = header_value
    if not header_value:
        return direct_ip, debug

    # X-Forwarded-For can contain a chain: client, proxy1, proxy2.
    if header_name.lower() == "x-forwarded-for":
        candidate = header_value.split(',')[0].strip()
    else:
        candidate = header_value.strip()

    try:
        ipaddress.ip_address(candidate)
        return candidate, debug
    except Exception:
        return direct_ip, debug


def validate_inbound_webhook_request(request: Request) -> Dict[str, Any]:
    settings = get_settings_data()
    webhook = settings.get("webhook", {}) or {}

    if not bool(webhook.get("enabled", True)):
        raise HTTPException(status_code=403, detail="Webhook de alertas está desabilitado.")

    client_ip, ip_debug = _extract_real_ip(request, webhook)
    trusted_sources = _as_list(webhook.get("trusted_sources"))

    if _ip_in_sources(client_ip, trusted_sources):
        return {
            "allowed": True,
            "reason": "trusted_source",
            "client_ip": client_ip,
            "details": ip_debug,
        }

    expected_token = str(webhook.get("token") or "")
    provided_token = str(request.headers.get(WEBHOOK_TOKEN_HEADER) or "")
    require_token_external = bool(webhook.get("require_token_external", True))

    if require_token_external:
        if not expected_token:
            raise HTTPException(
                status_code=403,
                detail="Origem não confiável e token do webhook não está configurado.",
            )
        if not provided_token or not hmac.compare_digest(provided_token, expected_token):
            raise HTTPException(status_code=401, detail="Token do webhook ausente ou inválido.")

    return {
        "allowed": True,
        "reason": "token" if require_token_external else "token_not_required",
        "client_ip": client_ip,
        "details": ip_debug,
    }
