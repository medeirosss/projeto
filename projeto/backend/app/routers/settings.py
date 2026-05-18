from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

from app.services.common import write_text_log
from app.services.module_service import get_module_status
from app.services.scanner_service import fetch_endpointcentral_all, get_access_token, run_ad_scan
from app.services.settings_service import get_settings_data, save_settings_data, settings_public_view

router = APIRouter(prefix="/api", tags=["settings"])


@router.get("/settings")
async def api_get_settings():
    settings = get_settings_data()
    response = settings_public_view(settings)
    response["module_status"] = get_module_status(settings)
    return response


@router.post("/settings")
async def api_save_settings(payload: Dict[str, Any] = Body(...)):
    settings = save_settings_data(payload or {})
    return {
        "success": True,
        "message": "Configurações salvas com sucesso.",
        "settings": settings_public_view(settings),
    }


@router.post("/settings/test-ad")
async def api_test_ad():
    settings = get_settings_data()
    try:
        records, source = run_ad_scan(settings)
        log = write_text_log(
            "ADstatus",
            "\n".join(
                [
                    "=== AD TEST ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Source: {source}",
                    f"AD total: {len(records)}",
                    "Storage: PostgreSQL scan_snapshots",
                ]
            ),
        )
        return {"success": True, "reachable": True, "total": len(records), "log_file": log.name}
    except Exception as exc:
        log = write_text_log(
            "ADstatus",
            "\n".join(
                [
                    "=== AD TEST ERROR ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Error: {str(exc)}",
                ]
            ),
        )
        return JSONResponse(status_code=500, content={"detail": f"Falha no teste do AD. Log: {log.name}"})


@router.post("/settings/test-ec")
async def api_test_ec():
    settings = get_settings_data()
    try:
        records, token_source, api_log, token_debug_log = fetch_endpointcentral_all(settings)
        return {
            "success": True,
            "reachable": True,
            "total": len(records),
            "token_source": token_source,
            "log_file": api_log,
            "token_debug_log": token_debug_log,
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"detail": str(exc)})


@router.post("/token/refresh")
async def api_token_refresh():
    settings = get_settings_data()
    token, source, token_debug_log = get_access_token(settings)
    if not token:
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Falha ao gerar access token.", "token_debug_log": token_debug_log},
        )
    return {"success": True, "token_source": source, "token_debug_log": token_debug_log}
