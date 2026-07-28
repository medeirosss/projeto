from __future__ import annotations
import os
import re
from app.repositories import target_repository as repo
from app.services.nmap_provider import LocalNmapProvider, validate_target_spec, target_type, target_address_count, DiscoveryExecutionError
from app.services.runner_discovery_provider import RunnerDiscoveryProvider

def normalize_hostname(hostname):
    value=(hostname or "").strip().rstrip(".").lower(); return value or None

def normalize_mac(mac):
    if not mac:return None,None
    compact=re.sub(r"[^0-9a-fA-F]","",mac).upper()
    if len(compact)!=12:return None,None
    return ":".join(compact[i:i+2] for i in range(0,12,2)),compact

def _provider_name():
    return os.getenv("DISCOVERY_PROVIDER","runner").strip().lower()

def execute_scan(scan:dict,trigger_type="manual"):
    provider=_provider_name()
    if provider == "runner":
        try:
            return RunnerDiscoveryProvider().enqueue(scan,trigger_type)
        except DiscoveryExecutionError as exc:
            spec=validate_target_spec(scan["target_spec"])
            run=repo.create_discovery_run(spec,int(scan["id"]),trigger_type,target_address_count(spec))
            repo.finish_discovery_run(run["run_uuid"],"waiting_runner",0,str(exc)[:2000])
            repo.release_scan(int(scan["id"]),scan.get("interval_minutes") if scan.get("is_enabled") else None)
            raise
    if provider not in {"local","auto"}:
        raise ValueError("DISCOVERY_PROVIDER deve ser runner, local ou auto.")
    spec=validate_target_spec(scan["target_spec"]); sid=int(scan["id"])
    run=repo.create_discovery_run(spec,sid,trigger_type,target_address_count(spec))
    try:
        discovered=LocalNmapProvider().discover(spec); items=[]
        for host in discovered:
            fm,nm=normalize_mac(host.mac_address)
            items.append(repo.upsert_discovered_target(hostname=host.hostname,hostname_normalized=normalize_hostname(host.hostname),dns_name=host.hostname,ip_address=host.ip_address,mac_address=fm,mac_normalized=nm,vendor=host.vendor,status="online",source="nmap-local",scan_id=sid,runner_id=None))
        repo.finish_discovery_run(run["run_uuid"],"success",len(items)); return {"success":True,"run_uuid":run["run_uuid"],"discovered_count":len(items),"items":items,"provider":"local"}
    except Exception as exc:
        repo.finish_discovery_run(run["run_uuid"],"failed",0,str(exc)[:2000]); raise
    finally:
        repo.release_scan(sid,scan.get("interval_minutes") if scan.get("is_enabled") else None)

def ingest_runner_discovery_result(job_id:int, runner_id:str, status:str, result:dict, error:str|None=None):
    run=repo.get_discovery_run_by_job(job_id)
    if not run: return None
    metadata=(result or {}).get("metadata") or {}
    hosts=metadata.get("hosts") or []
    items=[]
    if status=="success":
        for host in hosts:
            ip=host.get("ip_address")
            if not ip or host.get("status")!="up": continue
            fm,nm=normalize_mac(host.get("mac_address"))
            items.append(repo.upsert_discovered_target(hostname=host.get("hostname"),hostname_normalized=normalize_hostname(host.get("hostname")),dns_name=host.get("dns_name") or host.get("hostname"),hostname_source=host.get("hostname_source"),ip_address=ip,mac_address=fm,mac_normalized=nm,vendor=host.get("vendor"),status="online",source="nmap-runner",scan_id=run.get("scan_id"),runner_id=runner_id))
        final_status="success"
    elif status=="timeout": final_status="timeout"
    else: final_status="failed"
    updated=repo.update_discovery_run_from_runner(job_id,final_status,len(items),error or result.get("error") or result.get("stderr"),metadata.get("raw_xml"),runner_id)
    repo.release_scan_by_run(run)
    return {"run":updated,"items":items}

def create_scan(payload):
    spec=validate_target_spec(str(payload.get("target_spec") or "")); name=(payload.get("name") or spec).strip()[:150]
    if target_type(spec)=="network" and target_address_count(spec)>256: raise ValueError("A versão 1.0 permite redes de até /24.")
    sched=payload.get("schedule_type") or "manual"; interval=payload.get("interval_minutes")
    if sched not in {"manual","interval"}: raise ValueError("Tipo de agendamento inválido.")
    if sched=="interval":
        interval=int(interval or 0)
        if interval<15: raise ValueError("O intervalo mínimo é de 15 minutos.")
    else: interval=None
    return repo.create_scan(name,spec,target_type(spec),sched,interval,bool(payload.get("is_enabled") and sched=="interval"))

list_targets=repo.list_targets; get_target=repo.get_target; list_discovery_runs=repo.list_discovery_runs
