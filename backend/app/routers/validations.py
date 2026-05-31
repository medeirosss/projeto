from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request

from app.services.atomic_service import (
    dispatch_atomic_execution_to_runner,
    execute_atomic_lab_test,
    get_atomic_execution_previews,
    get_atomic_summary,
    get_atomic_techniques,
    get_atomic_tests,
    import_atomic_catalog,
    prepare_atomic_execution_preview,
    set_atomic_test_approval,
    set_atomic_test_flags,
    set_atomic_test_risk,
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



@router.post("/atomic/tests/{test_id}/approve")
async def api_atomic_test_approve(test_id: int, payload: dict[str, Any] | None = Body(default=None)):
    try:
        payload = payload or {}
        return set_atomic_test_approval(test_id, bool(payload.get("approved", True)))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/atomic/tests/{test_id}/risk")
async def api_atomic_test_risk(test_id: int, payload: dict[str, Any] = Body(...)):
    try:
        return set_atomic_test_risk(test_id, payload.get("risk_level"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/atomic/tests/{test_id}/flags")
async def api_atomic_test_flags(test_id: int, payload: dict[str, Any] | None = Body(default=None)):
    try:
        return set_atomic_test_flags(test_id, payload or {})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))




@router.post("/atomic/tests/{test_id}/execute-lab")
async def api_atomic_execute_lab(test_id: int, request: Request, payload: dict[str, Any] | None = Body(default=None)):
    try:
        payload = payload or {}
        user_state = getattr(request.state, "user", {}) or {}
        payload["current_user"] = {
            "username": user_state.get("sub") or user_state.get("username") or payload.get("approved_by") or "ui",
            "role": str(user_state.get("role") or payload.get("role") or "viewer").lower(),
        }
        return execute_atomic_lab_test(test_id, payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/atomic/tests/{test_id}/prepare-execution")
async def api_atomic_prepare_execution(test_id: int, payload: dict[str, Any] | None = Body(default=None)):
    try:
        return prepare_atomic_execution_preview(test_id, payload or {})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/atomic/executions")
async def api_atomic_executions(limit: int = 100, offset: int = 0):
    return get_atomic_execution_previews(limit=limit, offset=offset)



@router.post("/atomic/executions/{execution_id}/dispatch")
async def api_atomic_dispatch_execution(execution_id: int, payload: dict[str, Any] | None = Body(default=None)):
    try:
        return dispatch_atomic_execution_to_runner(execution_id, payload or {})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
