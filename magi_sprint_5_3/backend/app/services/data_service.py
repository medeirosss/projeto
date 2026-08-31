from __future__ import annotations

from typing import Any, Dict, List, Set

from app.repositories.reports_repository import get_latest_scan_records
from app.services.common import normalize_hostname


def get_ad_records() -> List[Dict[str, Any]]:
    """Return latest AD scan snapshot from PostgreSQL.

    Clean v2 rule: PostgreSQL is the source of truth for scans/reports.
    Legacy JSON files are no longer used as official data source.
    """
    return get_latest_scan_records("ad")


def get_ec_records() -> List[Dict[str, Any]]:
    """Return latest Endpoint Central/UEM snapshot from PostgreSQL."""
    return get_latest_scan_records("endpointcentral")


def get_ad_hostnames() -> Set[str]:
    result: Set[str] = set()
    for item in get_ad_records():
        hostname = normalize_hostname(item.get("hostname") or item.get("name") or item.get("cn"))
        if hostname:
            result.add(hostname)
    return result


def get_ec_hostnames() -> Set[str]:
    result: Set[str] = set()
    for item in get_ec_records():
        hostname = normalize_hostname(item.get("full_name"))
        if hostname:
            result.add(hostname)
    return result
