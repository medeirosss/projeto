from __future__ import annotations
import re
from app.repositories import target_repository as repo
from app.services.nmap_provider import LocalNmapProvider, validate_target_spec, target_type, target_address_count


def normalize_hostname(hostname):
    value=(hostname or "").strip().rstrip(".").lower(); return value or None

def normalize_mac(mac):
    if not mac:return None,None
    compact=re.sub(r"[^0-9a-fA-F]","",mac).upper()
    if len(compact)!=12:return None,None
    return ":".join(compact[i:i+2] for i in range(0,12,2)),compact


def execute_scan(scan:dict,trigger_type="manual"):
    spec=validate_target_spec(scan["target_spec"]); sid=int(scan["id"])
    run=repo.create_discovery_run(spec,sid,trigger_type,target_address_count(spec))
    try:
        discovered=LocalNmapProvider().discover(spec); items=[]
        for host in discovered:
            fm,nm=normalize_mac(host.mac_address)
            items.append(repo.upsert_discovered_target(hostname=host.hostname,hostname_normalized=normalize_hostname(host.hostname),ip_address=host.ip_address,mac_address=fm,mac_normalized=nm,source="nmap",scan_id=sid))
        repo.finish_discovery_run(run["run_uuid"],"success",len(items)); return {"success":True,"run_uuid":run["run_uuid"],"discovered_count":len(items),"items":items}
    except Exception as exc:
        repo.finish_discovery_run(run["run_uuid"],"failed",0,str(exc)[:2000]); raise
    finally:
        repo.release_scan(sid,scan.get("interval_minutes") if scan.get("is_enabled") else None)


def create_scan(payload):
    spec=validate_target_spec(str(payload.get("target_spec") or "")); name=(payload.get("name") or spec).strip()[:150]
    sched=payload.get("schedule_type") or "manual"; interval=payload.get("interval_minutes")
    if sched not in {"manual","interval"}: raise ValueError("Tipo de agendamento inválido.")
    if sched=="interval":
        interval=int(interval or 0)
        if interval<15: raise ValueError("O intervalo mínimo é de 15 minutos.")
    else: interval=None
    return repo.create_scan(name,spec,target_type(spec),sched,interval,bool(payload.get("is_enabled") and sched=="interval"))

list_targets=repo.list_targets; get_target=repo.get_target; list_discovery_runs=repo.list_discovery_runs
