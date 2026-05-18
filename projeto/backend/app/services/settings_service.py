from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from app.repositories.settings_repository import get_settings_rows, save_settings_rows
from app.security.crypto_service import decrypt_secret, encrypt_secret, is_encrypted

DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": {"dark_mode": True},
    "modules": {
        "uem": {"enabled": True, "label": "UEM"},
        "security": {"enabled": True, "label": "Security"},
    },
    "mail_server": {
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "sender": "",
        "from_email": "",
        "use_tls": True,
        "use_ssl": False,
        "whatsapp_enabled": False,
        "n8n_webhook_url": "",
    },
    "webhook": {
        "enabled": True,
        "token": "",
        "trusted_sources": ["127.0.0.1/32", "::1/128"],
        "require_token_external": True,
        "proxy_enabled": False,
        "trusted_proxies": [],
        "real_ip_header": "X-Forwarded-For",
    },
    "uem": {
        "api": {
            "accounts_url": "",
            "base_url": "",
            "client_id": "",
            "client_secret": "",
            "refresh_token": "",
        },
        "active_directory": {
            "dc_host": "",
            "ldap_port": 389,
            "use_ssl": False,
            "domain_name": "",
            "base_dn": "",
            "domain_username": "",
            "domain_password": "",
        },
        "parameters": {
            "cutoff_days": None,
            "refresh_hours": 1,
            "page_size": 25,
            "debug_mode": True,
        },
        "ip_scope": {"cidrs": []},
    },
}

LEGACY_KEY_MAP = {
    "dc_host": ("uem", "active_directory", "dc_host"),
    "domain_username": ("uem", "active_directory", "domain_username"),
    "domain_password": ("uem", "active_directory", "domain_password"),
    "ldap_port": ("uem", "active_directory", "ldap_port"),
    "use_ssl": ("uem", "active_directory", "use_ssl"),
    "domain_name": ("uem", "active_directory", "domain_name"),
    "base_dn": ("uem", "active_directory", "base_dn"),
    "manual_refresh_token": ("uem", "api", "refresh_token"),
    "cutoff": ("uem", "parameters", "cutoff_days"),
    "refresh_hours": ("uem", "parameters", "refresh_hours"),
    "page_size": ("uem", "parameters", "page_size"),
    "debug_mode": ("uem", "parameters", "debug_mode"),
}

SENSITIVE_PATHS = {
    ("mail_server", "password"),
    ("uem", "api", "client_secret"),
    ("uem", "api", "refresh_token"),
    ("uem", "active_directory", "domain_password"),
    ("webhook", "token"),
}

PUBLIC_MASK = "********"


def deep_merge(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    result = deepcopy(base)
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _set_nested(container: Dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = container
    for key in path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[path[-1]] = value


def _get_nested(container: Dict[str, Any], path: tuple[str, ...]) -> Any:
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def migrate_legacy_settings(raw: Dict[str, Any]) -> Dict[str, Any]:
    migrated = deepcopy(DEFAULT_SETTINGS)
    nested = {k: v for k, v in (raw or {}).items() if k not in LEGACY_KEY_MAP}
    migrated = deep_merge(migrated, nested)
    for legacy_key, path in LEGACY_KEY_MAP.items():
        if legacy_key in (raw or {}):
            _set_nested(migrated, path, raw.get(legacy_key))
    return migrated


def _decrypt_sensitive_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    for path in SENSITIVE_PATHS:
        value = _get_nested(data, path)
        if isinstance(value, str) and value:
            _set_nested(data, path, decrypt_secret(value))
    return data


def _encrypt_sensitive_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    for path in SENSITIVE_PATHS:
        value = _get_nested(data, path)
        if isinstance(value, str) and value:
            _set_nested(data, path, encrypt_secret(value))
    return data


def _normalize_ip_scope(data: Dict[str, Any]) -> Dict[str, Any]:
    scope = data.get("uem", {}).get("ip_scope", {})
    if isinstance(scope, list):
        data.setdefault("uem", {})["ip_scope"] = {"cidrs": scope}
    elif isinstance(scope, dict):
        cidrs = scope.get("cidrs", [])
        if not isinstance(cidrs, list):
            scope["cidrs"] = []
    else:
        data.setdefault("uem", {})["ip_scope"] = {"cidrs": []}
    return data


def _normalize_types(data: Dict[str, Any]) -> Dict[str, Any]:
    ad = data.setdefault("uem", {}).setdefault("active_directory", {})
    params = data.setdefault("uem", {}).setdefault("parameters", {})
    mail = data.setdefault("mail_server", {})
    webhook = data.setdefault("webhook", {})
    try:
        ad["ldap_port"] = int(ad.get("ldap_port") or 389)
    except Exception:
        ad["ldap_port"] = 389
    ad["use_ssl"] = bool(ad.get("use_ssl"))
    try:
        mail["port"] = int(mail.get("port") or 587)
    except Exception:
        mail["port"] = 587
    mail["use_tls"] = bool(mail.get("use_tls", True))
    mail["use_ssl"] = bool(mail.get("use_ssl", False))
    mail["whatsapp_enabled"] = bool(mail.get("whatsapp_enabled", False))
    webhook["enabled"] = bool(webhook.get("enabled", True))
    webhook["require_token_external"] = bool(webhook.get("require_token_external", True))
    webhook["proxy_enabled"] = bool(webhook.get("proxy_enabled", False))
    for list_key in ("trusted_sources", "trusted_proxies"):
        value = webhook.get(list_key, [])
        if isinstance(value, str):
            webhook[list_key] = [line.strip() for line in value.replace(',', '\n').splitlines() if line.strip()]
        elif isinstance(value, list):
            webhook[list_key] = [str(item).strip() for item in value if str(item).strip()]
        else:
            webhook[list_key] = []
    allowed_headers = {"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"}
    if webhook.get("real_ip_header") not in allowed_headers:
        webhook["real_ip_header"] = "X-Forwarded-For"
    for key, default in (("refresh_hours", 1), ("page_size", 25)):
        try:
            params[key] = int(params.get(key) or default)
        except Exception:
            params[key] = default
    params["debug_mode"] = bool(params.get("debug_mode", True))
    return data


def get_settings_data() -> Dict[str, Any]:
    raw = get_settings_rows()
    if not isinstance(raw, dict):
        raw = {}
    data = migrate_legacy_settings(raw)
    data = deep_merge(DEFAULT_SETTINGS, data)
    data = _normalize_ip_scope(data)
    data = _normalize_types(data)
    return _decrypt_sensitive_fields(data)


def save_settings_data(incoming: Dict[str, Any]) -> Dict[str, Any]:
    current = get_settings_data()
    incoming = incoming or {}
    merged = deep_merge(current, incoming)

    # Preserve existing sensitive values when the UI submits blank or masked values.
    for path in SENSITIVE_PATHS:
        cursor = merged
        src_cursor: Any = incoming
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
            src_cursor = src_cursor.get(part, {}) if isinstance(src_cursor, dict) else {}
        field = path[-1]
        submitted = src_cursor.get(field, None) if isinstance(src_cursor, dict) else None
        if submitted in (None, "", PUBLIC_MASK):
            original_cursor: Any = current
            for part in path[:-1]:
                original_cursor = original_cursor.get(part, {}) if isinstance(original_cursor, dict) else {}
            cursor[field] = original_cursor.get(field, "") if isinstance(original_cursor, dict) else ""

    merged = _normalize_ip_scope(merged)
    merged = _normalize_types(merged)
    encrypted = _encrypt_sensitive_fields(deepcopy(merged))
    save_settings_rows(encrypted)
    return merged


def get_uem_api_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    return settings.get("uem", {}).get("api", {})


def get_uem_ad_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    return settings.get("uem", {}).get("active_directory", {})


def get_uem_parameters(settings: Dict[str, Any]) -> Dict[str, Any]:
    return settings.get("uem", {}).get("parameters", {})


def is_uem_enabled(settings: Dict[str, Any]) -> bool:
    return bool(settings.get("modules", {}).get("uem", {}).get("enabled", True))


def is_security_enabled(settings: Dict[str, Any]) -> bool:
    return bool(settings.get("modules", {}).get("security", {}).get("enabled", True))


def settings_public_view(settings: Dict[str, Any]) -> Dict[str, Any]:
    data = deepcopy(settings)
    api = data.setdefault("uem", {}).setdefault("api", {})
    ad = data.setdefault("uem", {}).setdefault("active_directory", {})
    mail = data.setdefault("mail_server", {})
    webhook = data.setdefault("webhook", {})

    has_password = bool(ad.get("domain_password"))
    has_refresh_token = bool(api.get("refresh_token"))
    has_client_secret = bool(api.get("client_secret"))
    has_mail_password = bool(mail.get("password"))
    has_webhook_token = bool(webhook.get("token"))

    if has_password:
        ad["domain_password"] = PUBLIC_MASK
    if has_refresh_token:
        api["refresh_token"] = PUBLIC_MASK
    if has_client_secret:
        api["client_secret"] = PUBLIC_MASK
    if has_mail_password:
        mail["password"] = PUBLIC_MASK
    if has_webhook_token:
        webhook["token"] = PUBLIC_MASK

    data.update(
        {
            "configured": bool(ad.get("dc_host") and ad.get("domain_username")) or bool(has_refresh_token),
            "has_password": has_password,
            "has_refresh_token": has_refresh_token,
            "has_client_secret": has_client_secret,
            "has_mail_password": has_mail_password,
            "has_webhook_token": has_webhook_token,
            "storage": "postgresql",
        }
    )
    return data
