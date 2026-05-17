from __future__ import annotations

import os
from typing import Any, Dict, List
from urllib.parse import urlparse

from ldap3 import ALL, SUBTREE, Connection, Server, Tls

from app.services.settings_service import get_settings_data, get_uem_ad_settings


def _domain_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in (domain or "").split(".") if part)


def _normalize_bind_user(username: str, domain_name: str) -> str:
    username = (username or "").strip()
    domain_name = (domain_name or "").strip()
    if not username:
        return ""
    if "@" in username:
        return username
    if "\\" in username:
        _, sam = username.split("\\", 1)
        return f"{sam}@{domain_name}" if domain_name else sam
    return f"{username}@{domain_name}" if domain_name else username


def _sam_from_username(username: str) -> str:
    username = (username or "").strip()
    if "\\" in username:
        return username.split("\\", 1)[1]
    if "@" in username:
        return username.split("@", 1)[0]
    return username


def _parse_ldap_target(dc_host: str, use_ssl_default: bool, port_default: int) -> tuple[str, int, bool]:
    raw = (dc_host or "").strip()
    if not raw:
        raise RuntimeError("Servidor AD não configurado.")
    if raw.startswith(("ldap://", "ldaps://")):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        use_ssl = parsed.scheme == "ldaps"
    else:
        if ":" in raw and raw.count(":") == 1:
            host, port_text = raw.rsplit(":", 1)
            port = int(port_text)
            use_ssl = port == 636
        else:
            host = raw
            port = int(port_default or (636 if use_ssl_default else 389))
            use_ssl = bool(use_ssl_default)
    return host, port, use_ssl


def _get_auth_ad_settings() -> Dict[str, Any]:
    settings = get_settings_data()
    ad = get_uem_ad_settings(settings)
    domain_name = str(ad.get("domain_name") or os.getenv("EXPECTED_AD_DOMAIN", "")).strip()
    base_dn = str(ad.get("base_dn") or _domain_to_base_dn(domain_name)).strip()
    use_ssl = bool(ad.get("use_ssl", False))
    try:
        ldap_port = int(ad.get("ldap_port") or (636 if use_ssl else 389))
    except Exception:
        ldap_port = 636 if use_ssl else 389
    return {
        "dc_host": str(ad.get("dc_host") or "").strip(),
        "domain_name": domain_name,
        "base_dn": base_dn,
        "use_ssl": use_ssl,
        "ldap_port": ldap_port,
    }


def authenticate_and_get_groups(username: str, password: str) -> Dict[str, Any]:
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        raise RuntimeError("Usuário e senha são obrigatórios.")

    ad = _get_auth_ad_settings()
    host, port, use_ssl = _parse_ldap_target(ad["dc_host"], ad["use_ssl"], ad["ldap_port"])
    bind_user = _normalize_bind_user(username, ad["domain_name"])
    tls_config = Tls(validate=0) if use_ssl else None
    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls_config, connect_timeout=15)

    try:
        conn = Connection(server, user=bind_user, password=password, authentication="SIMPLE", auto_bind=True, receive_timeout=20)
    except Exception as exc:
        protocol = "LDAPS" if use_ssl else "LDAP"
        raise RuntimeError(f"Falha na autenticação AD via {protocol}: {exc}") from exc

    groups: List[str] = []
    display_name = _sam_from_username(username)
    try:
        if ad["base_dn"]:
            sam = _sam_from_username(username)
            conn.search(
                search_base=ad["base_dn"],
                search_filter=f"(&(objectClass=user)(sAMAccountName={sam}))",
                search_scope=SUBTREE,
                attributes=["memberOf", "displayName", "userPrincipalName", "sAMAccountName"],
            )
            if conn.entries:
                entry = conn.entries[0]
                display_name = str(getattr(entry, "displayName", "") or sam)
                raw_groups = getattr(entry, "memberOf", []) or []
                for item in raw_groups:
                    text = str(item)
                    # CN=Grupo,OU=... -> Grupo
                    if text.upper().startswith("CN="):
                        text = text.split(",", 1)[0][3:]
                    groups.append(text)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    return {
        "username": bind_user.lower(),
        "samaccountname": _sam_from_username(username),
        "display_name": display_name,
        "groups": sorted(set(g for g in groups if g)),
    }
