from __future__ import annotations

import asyncio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import APP_PORT, FRONTEND_DIR
from app.routers.dashboard import router as dashboard_router
from app.routers.health import router as health_router
from app.routers.pages import router as pages_router
from app.routers.reports import router as reports_router
from app.routers.settings import router as settings_router
from app.routers.actions import router as actions_router
from app.routers.alerts import router as alerts_router
from app.license.license_middleware import LicenseMiddleware
from app.security.auth_middleware import AuthMiddleware
from app.auth.auth_router import router as auth_router
from app.license.license_router import router as license_router
from app.license.license_scheduler import run_license_scheduler
from app.license.license_service import license_service
from app.repositories.auth_repository import ensure_local_auth_schema

app = FastAPI(title="Centric - UEM Backend")
app.add_middleware(AuthMiddleware)
app.add_middleware(LicenseMiddleware)


@app.on_event("startup")
async def startup_event():
    ensure_local_auth_schema()
    license_service.validate()
    asyncio.create_task(run_license_scheduler())


if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR)), name="assets")

app.include_router(license_router)
app.include_router(auth_router)
app.include_router(pages_router)
app.include_router(health_router)
app.include_router(settings_router)
app.include_router(dashboard_router)
app.include_router(reports_router)
app.include_router(actions_router)
app.include_router(alerts_router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=APP_PORT, reload=True)
