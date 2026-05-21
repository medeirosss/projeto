from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body

from app.services.cve_intelligence_service import analyze_cve, enrich_cve_rows, list_rules

router = APIRouter(prefix="/api/cve-intelligence", tags=["cve-intelligence"])


@router.get("/rules")
async def api_cve_intelligence_rules():
    return list_rules()


@router.post("/analyze")
async def api_cve_intelligence_analyze(payload: Dict[str, Any] = Body(...)):
    return {"success": True, "intelligence": analyze_cve(payload or {})}


@router.post("/batch")
async def api_cve_intelligence_batch(payload: Dict[str, Any] = Body(...)):
    rows: List[Dict[str, Any]] = payload.get("cves") or []
    return {"success": True, "cves": enrich_cve_rows(rows)}
