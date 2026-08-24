from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Request

from app.services.attack_simulator_service import attack_catalog, attack_history, sync_attack_simulator
from app.services.validation_engine_service import execute_task, plan_task

router = APIRouter(prefix="/api/attack-simulator", tags=["attack-simulator"])


@router.get("/summary")
def summary():
    data = attack_catalog()
    sims = data.get("simulations") or []
    categories: dict[str, int] = {}
    for item in sims:
        key = item.get("category") or "Other"
        categories[key] = categories.get(key, 0) + 1
    return {
        "success": True,
        "version": "5.1",
        "safe_mode": True,
        "destructive": False,
        "credential_execution": True,
        "simulations": len(sims),
        "categories": categories,
    }


@router.post("/sync")
def sync():
    return sync_attack_simulator()


@router.get("/catalog")
def catalog(search: str | None = None, category: str | None = None):
    return attack_catalog(search=search, category=category)


@router.post("/simulations/{task_id}/plan")
def plan(task_id: int, payload: dict = Body(...)):
    try:
        result = plan_task(task_id, payload.get("target"), options=payload)
        if result.get("task", {}).get("repository_key") != "magi_attack":
            raise ValueError("A tarefa informada não pertence ao MAGI Attack Simulator.")
        return result
    except Exception as exc:
        raise HTTPException(400, str(exc))


@router.post("/simulations/{task_id}/execute")
def execute(task_id: int, request: Request, payload: dict = Body(...)):
    try:
        planned = plan_task(task_id, payload.get("target"), options=payload)
        if planned.get("task", {}).get("repository_key") != "magi_attack":
            raise ValueError("A tarefa informada não pertence ao MAGI Attack Simulator.")
        u = getattr(request.state, "user", {}) or {}
        requested = u.get("sub") or u.get("username") or "ui"
        return execute_task(task_id, payload.get("target"), requested, options=payload)
    except Exception as exc:
        raise HTTPException(400, str(exc))


@router.get("/history")
def history(limit: int = 100):
    return attack_history(limit=max(1, min(limit, 500)))
