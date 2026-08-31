from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from ldap3 import ALL, BASE, SUBTREE, Connection, Server, Tls

from app.config import (
    EC_BASE_URL,
    REQUEST_TIMEOUT,
    ZOHO_ACCOUNTS_URL,
    ZOHO_CLIENT_ID,
    ZOHO_CLIENT_SECRET,
    ZOHO_REFRESH_TOKEN,
)
from app.services.common import normalize_hostname, write_text_log
from app.services.settings_service import get_uem_ad_settings, get_uem_api_settings
from app.repositories.reports_repository import save_scan_snapshot


def _domain_to_base_dn(domain: str) -> str:
    domain = (domain or "").strip()
    if not domain:
        return ""
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _extract_domain_from_username(username: str) -> str:
    username = (username or "").strip()
    if "@" in username:
        return username.split("@", 1)[1].strip()
    if "\\" in username:
        return username.split("\\", 1)[0].strip()
    return ""


def _normalize_bind_user(username: str, domain_name: str) -> str:
    """Return a bind user compatible with LDAP Simple Bind.

    The Linux container avoids NTLM because NTLM depends on MD4 in many
    ldap3/crypto stacks, which commonly fails on OpenSSL 3 environments.

    Accepted inputs:
    - DOMAIN\\user + domain_name: user@domain.local
    - user@domain.local: kept as-is
    - user + domain_name: user@domain.local
    """
    username = (username or "").strip()
    domain_name = (domain_name or "").strip()
    if not username:
        return ""
    if "@" in username:
        return username
    if "\\" in username:
        _, sam = username.split("\\", 1)
        if domain_name:
            return f"{sam}@{domain_name}"
        return sam
    if domain_name:
        return f"{username}@{domain_name}"
    return username


def _parse_ldap_target(dc_host: str, use_ssl_default: bool = False, port_default: int | None = None) -> tuple[str, int, bool]:
    raw = (dc_host or "").strip()
    if not raw:
        raise RuntimeError("DC host vazio.")

    # Accept dc.lab.local, dc.lab.local:636, ldap://dc:389, ldaps://dc:636
    if raw.startswith(("ldap://", "ldaps://")):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        use_ssl = parsed.scheme == "ldaps"
    else:
        if ":" in raw and raw.count(":") == 1:
            host, port_text = raw.rsplit(":", 1)
            port = int(port_text)
        else:
            host = raw
            port = int(port_default or (636 if use_ssl_default else 389))
        use_ssl = port == 636 if ":" in raw else use_ssl_default

    if not host:
        raise RuntimeError("DC host inválido.")
    return host, port, use_ssl


def _filetime_to_iso(value: Any) -> str:
    try:
        if value in (None, "", 0, "0"):
            return ""
        filetime = int(value)
        # Windows FILETIME: 100ns intervals since 1601-01-01 UTC.
        unix_ts = (filetime - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
    except Exception:
        return str(value or "")


def _ad_settings_effective(settings: Dict[str, Any]) -> Dict[str, Any]:
    ad_settings = get_uem_ad_settings(settings)
    dc_host = str(ad_settings.get("dc_host", "")).strip()
    username = str(ad_settings.get("domain_username", "")).strip()
    password = str(ad_settings.get("domain_password", "") or "")
    domain_name = str(
        ad_settings.get("domain_name")
        or os.getenv("EXPECTED_AD_DOMAIN", "")
        or _extract_domain_from_username(username)
    ).strip()
    base_dn = str(ad_settings.get("base_dn") or _domain_to_base_dn(domain_name)).strip()
    use_ssl = bool(ad_settings.get("use_ssl", False))
    try:
        ldap_port = int(ad_settings.get("ldap_port") or (636 if use_ssl else 389))
    except Exception:
        ldap_port = 636 if use_ssl else 389
    return {
        "dc_host": dc_host,
        "username": username,
        "password": password,
        "domain_name": domain_name,
        "base_dn": base_dn,
        "use_ssl": use_ssl,
        "ldap_port": ldap_port,
    }


def _open_ldap_connection(settings: Dict[str, Any]) -> Connection:
    ad = _ad_settings_effective(settings)
    if not ad["dc_host"] or not ad["username"]:
        raise RuntimeError("Configuração do AD incompleta. Informe DC host e usuário do domínio.")
    if not ad["password"]:
        raise RuntimeError("Senha do usuário de consulta do AD não informada.")

    host, port, use_ssl = _parse_ldap_target(ad["dc_host"], ad["use_ssl"], ad.get("ldap_port"))
    bind_user = _normalize_bind_user(ad["username"], ad["domain_name"])

    tls_config = Tls(validate=0) if use_ssl else None
    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls_config, connect_timeout=REQUEST_TIMEOUT)

    try:
        conn = Connection(
            server,
            user=bind_user,
            password=ad["password"],
            authentication="SIMPLE",
            auto_bind=True,
            receive_timeout=REQUEST_TIMEOUT,
        )
    except Exception as exc:
        protocol = "LDAPS" if use_ssl else "LDAP"
        raise RuntimeError(f"Falha ao autenticar no AD via {protocol} em {host}:{port}: {exc}") from exc

    return conn


def run_ad_scan(settings: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """Scan AD computers using LDAP/LDAPS directly from Python.

    This replaces the old Windows-only PowerShell/RSAT dependency and is compatible
    with the Linux container used by the clean v2 deployment.
    """
    ad = _ad_settings_effective(settings)
    base_dn = ad["base_dn"]
    if not base_dn:
        raise RuntimeError("Base DN do AD não encontrada. Configure o domínio ou base_dn.")

    conn = _open_ldap_connection(settings)
    try:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter="(&(objectCategory=computer)(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=["name", "dNSHostName", "lastLogonTimestamp"],
            paged_size=1000,
            generator=True,
        )

        normalized: List[Dict[str, Any]] = []
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            data = entry.get("attributes") or {}
            name = data.get("name")
            dns_name = data.get("dNSHostName")
            last_logon = data.get("lastLogonTimestamp")
            hostname = normalize_hostname(name)
            if hostname:
                normalized.append(
                    {
                        "hostname": hostname,
                        "dns_host_name": str(dns_name or "").strip(),
                        "last_logon_date": _filetime_to_iso(last_logon),
                    }
                )

        if not normalized:
            raise RuntimeError(f"Consulta LDAP não retornou computadores. Resultado: {conn.result}")

        _, _, effective_use_ssl = _parse_ldap_target(ad["dc_host"], ad["use_ssl"], ad.get("ldap_port"))
        source = "ldap3_ldaps" if effective_use_ssl else "ldap3_ldap"
        save_scan_snapshot("ad", normalized, source)
        return normalized, source
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def get_effective_zoho_credentials(settings: Dict[str, Any]) -> Dict[str, str]:
    api_settings = get_uem_api_settings(settings)
    return {
        "accounts_url": str(api_settings.get("accounts_url") or ZOHO_ACCOUNTS_URL).strip(),
        "base_url": str(api_settings.get("base_url") or EC_BASE_URL).strip().rstrip("/"),
        "client_id": str(api_settings.get("client_id") or ZOHO_CLIENT_ID).strip(),
        "client_secret": str(api_settings.get("client_secret") or ZOHO_CLIENT_SECRET).strip(),
        "refresh_token": str(api_settings.get("refresh_token") or ZOHO_REFRESH_TOKEN).strip(),
    }


def get_access_token(settings: Dict[str, Any]) -> Tuple[str, str, Optional[str]]:
    creds = get_effective_zoho_credentials(settings)
    if not creds["refresh_token"] or not creds["client_id"] or not creds["client_secret"]:
        return "", "missing_refresh_credentials", None
    try:
        res = requests.post(
            f"{creds['accounts_url'].rstrip('/')}/oauth/v2/token",
            data={
                "refresh_token": creds["refresh_token"],
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
                "grant_type": "refresh_token",
            },
            timeout=REQUEST_TIMEOUT,
        )
        try:
            payload = res.json()
        except Exception:
            payload = {"raw": res.text[:1000]}
        if not res.ok or "access_token" not in payload:
            log = write_text_log(
                "token_debug",
                "\n".join(
                    [
                        "=== TOKEN DEBUG ===",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"Status: {res.status_code}",
                        f"Response: {json.dumps(payload, ensure_ascii=False)}",
                    ]
                ),
            )
            return "", "refresh_token", log.name
        return str(payload["access_token"]).strip(), "refresh_token", None
    except Exception as exc:
        log = write_text_log(
            "token_debug",
            "\n".join(
                [
                    "=== TOKEN DEBUG ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Error: {str(exc)}",
                ]
            ),
        )
        return "", "refresh_token", log.name


def extract_ec_rows(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    message_response = payload.get("message_response")
    if not isinstance(message_response, dict):
        return []
    computers = message_response.get("computers")
    if not isinstance(computers, list):
        return []
    return [item for item in computers if isinstance(item, dict)]


def normalize_ec_record(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    hostname = normalize_hostname(item.get("full_name"))
    if not hostname:
        return None
    return {
        "full_name": hostname,
        "MAC": item.get("mac_address") or "",
        "IP": item.get("ip_address") or "",
        "agent_logged_on_users": item.get("agent_logged_on_users") or "",
        "resource_id": item.get("resource_id") or "",
        "live_status": item.get("computer_live_status") if item.get("computer_live_status") is not None else 0,
    }


def fetch_endpointcentral_all(
    settings: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], str, Optional[str], Optional[str]]:
    creds = get_effective_zoho_credentials(settings)
    access_token, token_source, token_debug_log = get_access_token(settings)
    if not access_token:
        raise RuntimeError(
            f"Não foi possível obter access token. token_source={token_source} token_debug_log={token_debug_log or ''}"
        )
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    all_rows: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    page = 1
    status_log_lines: List[str] = []
    body_previews: List[str] = []

    while True:
        url = f"{creds['base_url']}/api/1.4/som/computers?page={page}"
        res = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        content_type = res.headers.get("content-type", "")
        text_preview = (res.text or "")[:3000]
        status_log_lines.append(f"page={page} status={res.status_code} content_type={content_type}")
        if page <= 3:
            body_previews.append(f"--- PAGE {page} BODY PREVIEW ---\n{text_preview}\n")
        if not res.ok:
            api_log = write_text_log(
                "APIstatus",
                "\n".join(
                    [
                        "=== ENDPOINT CENTRAL FETCH ERROR ===",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"URL: {url}",
                        f"Status: {res.status_code}",
                        f"Content-Type: {content_type}",
                        f"Body preview: {text_preview}",
                    ]
                ),
            )
            raise RuntimeError(f"Falha ao consultar Endpoint Central. Log: {api_log.name}")
        try:
            payload = res.json()
        except Exception:
            try:
                payload = json.loads(res.text)
            except Exception:
                api_log = write_text_log(
                    "APIstatus",
                    "\n".join(
                        [
                            "=== ENDPOINT CENTRAL INVALID PAYLOAD ===",
                            f"Timestamp: {datetime.now().isoformat()}",
                            f"URL: {url}",
                            f"Status: {res.status_code}",
                            f"Content-Type: {content_type}",
                            f"Body preview: {text_preview}",
                        ]
                    ),
                )
                raise RuntimeError(f"Resposta inválida da API do Endpoint Central. Log: {api_log.name}")
        message_response = payload.get("message_response", {}) if isinstance(payload, dict) else {}
        rows = extract_ec_rows(payload)
        total = int(message_response.get("total", 0) or 0) if isinstance(message_response, dict) else 0
        limit = int(message_response.get("limit", 25) or 25) if isinstance(message_response, dict) else 25
        current_page = int(message_response.get("page", page) or page) if isinstance(message_response, dict) else page
        for row in rows:
            normalized = normalize_ec_record(row)
            if not normalized:
                continue
            unique_key = str(normalized.get("resource_id") or normalized.get("full_name"))
            if unique_key in seen_ids:
                continue
            seen_ids.add(unique_key)
            all_rows.append(normalized)
        if not rows or (total and len(all_rows) >= total) or len(rows) < limit:
            break
        total_pages = ((total + limit - 1) // limit) if total and limit else 0
        if total_pages and current_page >= total_pages:
            break
        page += 1
        if page > 1000:
            break
    save_scan_snapshot("endpointcentral", all_rows, "api")
    api_log = write_text_log(
        "APIstatus",
        "\n".join(
            [
                "=== ENDPOINT CENTRAL FETCH ===",
                f"Timestamp: {datetime.now().isoformat()}",
                f"Token source: {token_source}",
                f"Total records: {len(all_rows)}",
                "Storage: PostgreSQL scan_snapshots",
                "",
                *status_log_lines,
                "",
                *body_previews,
            ]
        ),
    )
    return all_rows, token_source, api_log.name, token_debug_log



def _first_value(data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        current: Any = data
        ok = True
        for part in key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                ok = False
                break
        if ok and current not in (None, "", [], {}):
            return current
    return ""


def _parse_cves(value: Any) -> List[str]:
    if isinstance(value, list):
        raw = " ".join(str(x) for x in value)
    else:
        raw = str(value or "")
    found = re.findall(r"CVE-\d{4}-\d{4,}", raw, flags=re.IGNORECASE)
    result: List[str] = []
    for cve in found:
        cve = cve.upper()
        if cve not in result:
            result.append(cve)
    return result


def _parse_cvss(value: Any) -> float:
    text = str(value or "").replace(",", ".")
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    try:
        return float(match.group(0))
    except Exception:
        return 0.0


def _bool_from_status(value: Any) -> bool | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if any(x in text for x in ("dispon", "available", "exploit", "yes", "true", "sim")) and not any(x in text for x in ("não", "nao", "not ", "indispon")):
        return True
    if any(x in text for x in ("não", "nao", "not available", "indispon", "false", "no")):
        return False
    return None


def _find_vulnerability_list(payload: Any) -> List[Dict[str, Any]]:
    preferred_paths = (
        "message_response.vulnerabilities",
        "message_response.vulnerability_details",
        "message_response.vulnerabilityDetails",
        "message_response.data",
        "vulnerabilities",
        "vulnerability_details",
        "vulnerabilityDetails",
        "data",
        "response.vulnerabilities",
        "response.data",
    )
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for path in preferred_paths:
        current: Any = payload
        ok = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                ok = False
                break
        if ok and isinstance(current, list):
            return [x for x in current if isinstance(x, dict)]
    for value in payload.values():
        if isinstance(value, list) and any(isinstance(x, dict) for x in value):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            nested = _find_vulnerability_list(value)
            if nested:
                return nested
    return []


def _normalize_vulnerability(vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
    name = str(_first_value(vuln, "vulnerabilityname", "vulnerability_name", "name", "title", "display_name") or "").strip()
    product = str(_first_value(vuln, "os_platform", "platform", "product", "software", "application", "affected_platform", "affectedPlatform") or name or "Unknown").strip()
    platform = str(_first_value(vuln, "platform", "os_platform", "os", "operating_system") or product or "Unknown").strip()
    severity = str(_first_value(vuln, "severity", "severity_name", "severityName", "risk", "risk_level") or "critical").strip()
    published = str(_first_value(vuln, "published", "published_date", "publishedDate", "release_date", "releaseDate", "publication_date") or "-").strip()
    exploit_status = str(_first_value(vuln, "exploit_status", "status_exploit", "exploitStatus", "exploit", "exploit_available", "exploits_available") or "").strip()
    patch_status = str(_first_value(vuln, "patch_status", "patch_availability", "patchAvailability", "patch_available", "availability_of_patch") or "").strip()
    cvss3_raw = _first_value(vuln, "cvss3", "cvss_3", "cvss3_score", "cvss_score", "cvssV3", "cvss")
    cvss2_raw = _first_value(vuln, "cvss2", "cvss_2", "cvss2_score", "cvssV2")
    cvss3 = _parse_cvss(cvss3_raw)
    cvss2 = _parse_cvss(cvss2_raw)
    affected = int(_parse_cvss(_first_value(vuln, "affected_systems", "systems_affected", "affected_count", "affectedSystems", "computer_count")))
    exploited_cves = _parse_cves(_first_value(vuln, "exploited_cve_ids", "exploitedCveIds", "exploited_cves", "exploited"))
    non_exploited_cves = _parse_cves(_first_value(vuln, "non_exploited_cve_ids", "nonExploitedCveIds", "non_exploited_cves"))
    all_cves = _parse_cves(_first_value(vuln, "cveids", "cve_ids", "cveIds", "cve", "cves", "cve_id", "cveId"))
    if not all_cves:
        all_cves = _parse_cves(" ".join([name, str(vuln.get("description") or ""), str(vuln.get("summary") or "")]))
    if not all_cves:
        return []
    exploit_available = _bool_from_status(exploit_status)
    if exploited_cves:
        exploit_available = True
    patch_available = _bool_from_status(patch_status)
    rows: List[Dict[str, Any]] = []
    for cve in all_cves:
        is_exploited = cve in exploited_cves
        rows.append({
            "id": cve,
            "product": product,
            "platform": platform,
            "severity": severity or "Crítico",
            "published": published,
            "name": name,
            "description": str(_first_value(vuln, "description", "summary") or name or ""),
            "cvss3": cvss3,
            "cvss2": cvss2,
            "cvss_vector": str(cvss3_raw or cvss2_raw or ""),
            "exploit_status": exploit_status or ("Disponível" if is_exploited else ""),
            "exploit_available": True if is_exploited else exploit_available,
            "patch_status": patch_status,
            "patch_available": patch_available,
            "affected_systems": affected,
            "is_exploited_cve": is_exploited,
        })
    return rows


def fetch_critical_cves(settings: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    creds = get_effective_zoho_credentials(settings)
    access_token, token_source, token_debug_log = get_access_token(settings)
    if not access_token:
        return [], {
            "source": "token_unavailable",
            "token_source": token_source,
            "token_debug_log": token_debug_log,
            "error": "Não foi possível obter access token para vulnerabilidades.",
        }

    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    url = f"{creds['base_url']}/dcapi/threats/vulnerabilities"
    page = 1
    page_limit = 100
    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    total_records = 0
    payload_shapes: List[str] = []

    try:
        while True:
            res = requests.get(
                url,
                headers=headers,
                params={"severity": "Critical", "page": page, "pageLimit": page_limit},
                timeout=REQUEST_TIMEOUT,
            )
            content_type = res.headers.get("content-type", "")
            preview = (res.text or "")[:3000]
            if not res.ok:
                log = write_text_log(
                    "VULNstatus",
                    "\n".join([
                        "=== VULNERABILITIES FETCH ERROR ===",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"Status: {res.status_code}",
                        f"Content-Type: {content_type}",
                        f"URL: {res.url}",
                        f"Body preview: {preview}",
                    ]),
                )
                return [], {"source": "api_error", "token_source": token_source, "token_debug_log": token_debug_log, "error": f"Falha ao consultar vulnerabilidades. Log: {log.name}"}

            payload = res.json()
            metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
            total_records = int(metadata.get("totalRecords") or metadata.get("total_records") or total_records or 0) if isinstance(metadata, dict) else total_records
            vulns = _find_vulnerability_list(payload)
            payload_shapes.append(f"page={page}; rows={len(vulns)}; keys={list(payload.keys()) if isinstance(payload, dict) else type(payload).__name__}")

            for vuln in vulns:
                for normalized in _normalize_vulnerability(vuln):
                    severity_text = str(normalized.get("severity") or "").lower()
                    # API já foi chamada com severity=Critical, mas mantemos filtro tolerante.
                    if not ("crit" in severity_text or severity_text in {"", "5"}):
                        continue
                    key = (str(normalized["id"]), str(normalized.get("product") or ""))
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(normalized)

            total_pages = int(metadata.get("totalPages") or metadata.get("total_pages") or 1) if isinstance(metadata, dict) else 1
            next_link = metadata.get("links", {}).get("next") if isinstance(metadata.get("links"), dict) else None
            if page >= total_pages:
                break
            if not next_link and total_pages <= 1:
                break
            page += 1
            if page > 100:
                break

        log = write_text_log(
            "VULNstatus",
            "\n".join([
                "=== VULNERABILITIES FETCH OK ===",
                f"Timestamp: {datetime.now().isoformat()}",
                f"URL: {url}",
                f"Rows parsed: {len(rows)}",
                f"Total records metadata: {total_records}",
                *payload_shapes,
            ]),
        )
        return rows, {"source": "endpoint_vulnerability_api", "token_source": token_source, "token_debug_log": token_debug_log, "total_records": total_records, "critical_rows": len(rows), "parser_log": log.name}
    except Exception as exc:
        log = write_text_log(
            "VULNstatus",
            "\n".join(["=== VULNERABILITIES FETCH ERROR ===", f"Timestamp: {datetime.now().isoformat()}", f"URL: {url}", f"Error: {str(exc)}"]),
        )
        return [], {"source": "exception", "token_source": token_source, "token_debug_log": token_debug_log, "error": f"Exceção ao consultar vulnerabilidades. Log: {log.name}"}
