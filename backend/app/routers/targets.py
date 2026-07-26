from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query

from app.services.nmap_provider import DiscoveryExecutionError, DiscoveryInputError
from app.services.target_service import discover_targets, get_target, list_discovery_runs, list_targets

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("")
async def api_list_targets(
    search: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return list_targets(search=search, limit=limit, offset=offset)


@router.get("/discovery-runs")
async def api_discovery_runs(limit: int = Query(default=20, ge=1, le=100)):
    return {"items": list_discovery_runs(limit)}


@router.post("/discover")
async def api_discover_targets(payload: dict = Body(...)):
    try:
        return discover_targets(str(payload.get("target_spec") or ""))
    except DiscoveryInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DiscoveryExecutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falha inesperada na descoberta: {exc}") from exc


@router.get("/{target_uuid}")
async def api_get_target(target_uuid: str):
    target = get_target(target_uuid)
    if not target:
        raise HTTPException(status_code=404, detail="Alvo não encontrado.")
    return target
