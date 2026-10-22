from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Set

from app.repositories.reports_repository import get_latest_scan_snapshot, save_scan_compare_run
from app.services.common import list_to_text, normalize_hostname
from app.services.data_service import get_ad_hostnames, get_ad_records, get_ec_hostnames, get_ec_records
from app.services.scanner_service import fetch_critical_cves
from app.services.cve_intelligence_service import enrich_cve_rows
from app.services.settings_service import get_uem_parameters


def build_dashboard_data(settings: Dict[str, Any]) -> Dict[str, Any]:
    ad_records = get_ad_records()
    ec_records = get_ec_records()
    ad_map = {normalize_hostname(x.get("hostname")): x for x in ad_records if normalize_hostname(x.get("hostname"))}
    ec_map = {normalize_hostname(x.get("full_name")): x for x in ec_records if normalize_hostname(x.get("full_name"))}
    ad_hosts = set(ad_map.keys())
    ec_hosts = set(ec_map.keys())
    only_in_ad_hosts = sorted(ad_hosts - ec_hosts)
    only_in_ec_hosts = sorted(ec_hosts - ad_hosts)
    in_both_hosts = sorted(ad_hosts & ec_hosts)
    params = get_uem_parameters(settings)
    ad_count = len(ad_hosts)
    ec_count = len(ec_hosts)
    in_both_count = len(in_both_hosts)
    install_percent = round((in_both_count / ad_count) * 100, 2) if ad_count else 0.0

    critical_cves, cve_meta = fetch_critical_cves(settings)
    critical_cves = enrich_cve_rows(critical_cves)

    return {
        "summary": {
            "ad_count": ad_count,
            "ec_count": ec_count,
            "without_agent_count": len(only_in_ad_hosts),
            "only_in_ad_count": len(only_in_ad_hosts),
            "not_in_ad_count": len(only_in_ec_hosts),
            "in_both_count": in_both_count,
            "install_percent": install_percent,
            "cutoff_days": params.get("cutoff_days"),
            "cutoff": params.get("cutoff_days"),
            "page_size": int(params.get("page_size") or 25),
            "debug_mode": bool(params.get("debug_mode")),
            "refresh_hours": int(params.get("refresh_hours") or 1),
            "json_file": "PostgreSQL",
            "log_file": "-",
            "critical_cves_total": len(critical_cves),
            "critical_cves_source": cve_meta.get("source", "none"),
        },
        "critical_cves": critical_cves,
        "critical_cves_meta": cve_meta,
        "only_in_ad": [ad_map[h] for h in only_in_ad_hosts],
        "only_in_ec": [ec_map[h] for h in only_in_ec_hosts],
    }


def build_active_users_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in sorted(get_ec_records(), key=lambda x: normalize_hostname(x.get("full_name"))):
        hostname = normalize_hostname(item.get("full_name"))
        if hostname:
            rows.append(
                {
                    "name": hostname,
                    "live_status": item.get("live_status", 0),
                    "user": list_to_text(item.get("agent_logged_on_users")),
                }
            )
    return rows


def read_csv_hostnames_from_bytes(content: bytes) -> Set[str]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV vazio ou inválido.")
    headers = [str(h).strip().lower() for h in reader.fieldnames if h]
    if "hostname" not in headers:
        raise ValueError("O CSV precisa conter o header 'hostname'.")
    result: Set[str] = set()
    for row in reader:
        hostname = normalize_hostname(row.get("hostname") or row.get("HOSTNAME") or row.get("Hostname"))
        if hostname:
            result.add(hostname)
    return result


def read_csv_hostnames_from_file(file_path: Path) -> Set[str]:
    if not file_path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path.name}")
    return read_csv_hostnames_from_bytes(file_path.read_bytes())


def build_scan_compare(csv_sources: Dict[str, Set[str]]) -> List[Dict[str, Any]]:
    ad_set = get_ad_hostnames()
    ec_set = get_ec_hostnames()
    sources: Dict[str, Set[str]] = {"AD": ad_set, "UEM": ec_set, **csv_sources}
    all_hostnames: Set[str] = set().union(*sources.values()) if sources else set()
    rows: List[Dict[str, Any]] = []
    source_names = list(sources.keys())
    for hostname in sorted(all_hostnames):
        present = [name for name in source_names if hostname in sources[name]]
        missing = [name for name in source_names if hostname not in sources[name]]
        if missing:
            rows.append(
                {
                    "hostname": hostname,
                    "presente_em": ", ".join(present) if present else "-",
                    "ausente_em": ", ".join(missing),
                    "present_in": present,
                    "missing_in": missing,
                    "no_ad": hostname in ad_set,
                    "no_uem": hostname in ec_set,
                }
            )
    save_scan_compare_run({name: sorted(values) for name, values in sources.items()}, rows)
    return rows
