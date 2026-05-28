from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException

from app.services.atomic_service import (
    get_atomic_summary,
    get_atomic_techniques,
    get_atomic_tests,
    import_atomic_catalog,
)

router = APIRouter(prefix="/api/validations", tags=["validations"])


@router.get("/atomic/summary")
async def api_atomic_summary():
    return get_atomic_summary()


@router.post("/atomic/import")
async def api_atomic_import(payload: dict[str, Any] | None = Body(default=None)):
    payload = payload or {}
    result = import_atomic_catalog(payload.get("source_path"))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result)
    return result


@router.get("/atomic/techniques")
async def api_atomic_techniques(search: str | None = None, limit: int = 200, offset: int = 0):
    return get_atomic_techniques(search=search, limit=limit, offset=offset)


@router.get("/atomic/tests")
async def api_atomic_tests(
    technique_id: str | None = None,
    platform: str | None = None,
    executor: str | None = None,
    risk_level: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    return get_atomic_tests(
        technique_id=technique_id,
        platform=platform,
        executor=executor,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
    )
