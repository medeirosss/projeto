from __future__ import annotations

import re

from app.repositories.target_repository import (
    create_discovery_run,
    finish_discovery_run,
    get_target,
    list_discovery_runs,
    list_targets,
    upsert_discovered_target,
)
from app.services.nmap_provider import LocalNmapProvider, validate_target_spec


def normalize_hostname(hostname: str | None) -> str | None:
    value = (hostname or "").strip().rstrip(".").lower()
    return value or None


def normalize_mac(mac: str | None) -> tuple[str | None, str | None]:
    if not mac:
        return None, None
    compact = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(compact) != 12:
        return None, None
    formatted = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    return formatted, compact


def discover_targets(target_spec: str) -> dict:
    validated = validate_target_spec(target_spec)
    run = create_discovery_run(validated)
    try:
        discovered = LocalNmapProvider().discover(validated)
        items = []
        for host in discovered:
            formatted_mac, normalized_mac = normalize_mac(host.mac_address)
            items.append(upsert_discovered_target(
                hostname=host.hostname,
                hostname_normalized=normalize_hostname(host.hostname),
                ip_address=host.ip_address,
                mac_address=formatted_mac,
                mac_normalized=normalized_mac,
                source="nmap",
            ))
        finish_discovery_run(run["run_uuid"], "success", len(items))
        return {"success": True, "run_uuid": run["run_uuid"], "target_spec": validated, "discovered_count": len(items), "items": items}
    except Exception as exc:
        finish_discovery_run(run["run_uuid"], "failed", 0, str(exc)[:2000])
        raise


__all__ = ["discover_targets", "get_target", "list_discovery_runs", "list_targets"]
