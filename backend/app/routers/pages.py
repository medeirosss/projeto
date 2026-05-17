from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from app.config import FRONTEND_DIR

router = APIRouter()


def serve_frontend_file(file_name: str) -> FileResponse:
    path = FRONTEND_DIR / file_name
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Arquivo frontend não encontrado: {file_name}")
    return FileResponse(path)


@router.get("/", response_class=HTMLResponse)
async def home_page():
    return serve_frontend_file("home.html")


@router.get("/home", response_class=HTMLResponse)
async def home_alias():
    return serve_frontend_file("home.html")


@router.get("/centric", response_class=HTMLResponse)
async def centric_alias():
    return serve_frontend_file("home.html")


@router.get("/relatorios", response_class=HTMLResponse)
async def reports_page():
    return serve_frontend_file("reports.html")


@router.get("/acoes", response_class=HTMLResponse)
async def actions_page():
    return serve_frontend_file("installer.html")


@router.get("/instalador", response_class=HTMLResponse)
async def installer_page():
    return serve_frontend_file("installer.html")




@router.get("/alertas", response_class=HTMLResponse)
async def alerts_page():
    return serve_frontend_file("alerts.html")

@router.get("/configuracoes", response_class=HTMLResponse)
async def settings_page():
    return serve_frontend_file("settings.html")
