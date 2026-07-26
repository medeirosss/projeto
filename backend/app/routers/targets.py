from __future__ import annotations
import asyncio
from fastapi import APIRouter, Body, HTTPException, Query
from app.repositories import target_repository as repo
from app.services.nmap_provider import DiscoveryExecutionError, DiscoveryInputError
from app.services.target_service import create_scan, execute_scan

router=APIRouter(prefix="/api/targets",tags=["targets"])

@router.get("")
async def api_list_targets(search:str|None=Query(None,max_length=255),limit:int=Query(200,ge=1,le=1000),offset:int=Query(0,ge=0)):
    return repo.list_targets(search,limit,offset)

@router.get("/discovery-runs")
@router.get("/discovery-runs/list")
async def api_runs(limit:int=Query(50,ge=1,le=500)): return {"items":repo.list_discovery_runs(limit)}

@router.delete("/discovery-runs")
async def api_clear_runs(): repo.clear_discovery_runs(); return {"success":True}

@router.get("/scans")
async def api_list_scans(): return {"items":repo.list_scans()}

@router.post("/scans")
async def api_create_scan(payload:dict=Body(...)):
    try:
        scan=create_scan(payload)
        if payload.get("run_now") and repo.mark_scan_running(scan["scan_uuid"]):
            result=await asyncio.to_thread(execute_scan,{**scan,"is_running":True},"manual")
            return {"scan":scan,"run":result}
        return {"scan":scan}
    except (DiscoveryInputError,ValueError) as exc: raise HTTPException(422,str(exc)) from exc
    except DiscoveryExecutionError as exc: raise HTTPException(502,str(exc)) from exc

@router.patch("/scans/{scan_uuid}")
async def api_update_scan(scan_uuid:str,payload:dict=Body(...)):
    try:
        if "target_spec" in payload:
            from app.services.nmap_provider import validate_target_spec, target_type
            payload["target_spec"]=validate_target_spec(payload["target_spec"]); payload["target_type"]=target_type(payload["target_spec"])
        effective_schedule=payload.get("schedule_type")
        if effective_schedule=="interval" and int(payload.get("interval_minutes") or 0)<15: raise ValueError("O intervalo mínimo é de 15 minutos.")
        scan=repo.update_scan(scan_uuid,**payload)
        if not scan: raise HTTPException(404,"Scan não encontrado.")
        return scan
    except (DiscoveryInputError,ValueError) as exc: raise HTTPException(422,str(exc)) from exc

@router.post("/scans/{scan_uuid}/run")
async def api_run_scan(scan_uuid:str):
    scan=repo.get_scan(scan_uuid)
    if not scan: raise HTTPException(404,"Scan não encontrado.")
    if not repo.mark_scan_running(scan_uuid): raise HTTPException(409,"Este scan já está em execução.")
    try: return await asyncio.to_thread(execute_scan,{**scan,"is_running":True},"manual")
    except DiscoveryExecutionError as exc: raise HTTPException(502,str(exc)) from exc

@router.delete("/scans/{scan_uuid}")
async def api_delete_scan(scan_uuid:str,remove_exclusive_targets:bool=Query(False)):
    if not repo.delete_scan(scan_uuid,remove_exclusive_targets): raise HTTPException(404,"Scan não encontrado.")
    return {"success":True}

@router.get("/{target_uuid}")
async def api_get_target(target_uuid:str):
    target=repo.get_target(target_uuid)
    if not target: raise HTTPException(404,"Alvo não encontrado.")
    return target

@router.delete("/{target_uuid}")
async def api_delete_target(target_uuid:str):
    if not repo.delete_target(target_uuid): raise HTTPException(404,"Alvo não encontrado.")
    return {"success":True}
