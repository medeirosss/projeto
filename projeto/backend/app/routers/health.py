from __future__ import annotations

from fastapi import APIRouter

from app.services.module_service import get_module_status
from app.services.settings_service import get_settings_data

router = APIRouter(prefix="", tags=["health"])


@router.get("/health")
async def health():
    settings = get_settings_data()
    return {
        "status": "ok",
        "module": "uem_backend",
        "modules": get_module_status(settings),
    }


@router.get("/api/modules/status")
async def module_status():
    settings = get_settings_data()
    return get_module_status(settings)
