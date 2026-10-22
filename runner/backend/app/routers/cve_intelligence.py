from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body

from app.services.cve_intelligence_service import analyze_cve, list_rules

router = APIRouter(prefix="/api/cve-intelligence", tags=["cve-intelligence"])


@router.get("/rules")
async def api_cve_intelligence_rules():
    return list_rules()


@router.post("/analyze")
async def api_cve_intelligence_analyze(payload: Dict[str, Any] = Body(...)):
    return {"success": True, "decision": analyze_cve(payload or {})}
