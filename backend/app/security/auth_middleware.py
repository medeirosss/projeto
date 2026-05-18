from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.security.jwt_service import JWT_COOKIE_NAME, decode_access_token

PUBLIC_AUTH_PATHS = (
    "/login",
    "/api/auth/login",
    "/api/auth/logout",
    "/change-password",
    "/api/auth/change-password",
    "/license",
    "/license/status",
    "/license/upload",
    "/health",
    "/api/actions/inbound-alert",
)

ROLE_ACCESS = {
    "admin": {"centric", "reports", "actions", "alerts", "settings"},
    "operator": {"centric", "reports", "actions", "alerts"},
    "viewer": {"centric", "reports"},
}


def _module_for_path(path: str) -> str | None:
    if path in ("/", "/home", "/centric") or path.startswith("/api/dashboard") or path.startswith("/api/modules"):
        return "centric"
    if path.startswith("/relatorios") or path.startswith("/api/reports"):
        return "reports"
    if path.startswith("/acoes") or path.startswith("/instalador") or path.startswith("/api/actions"):
        return "actions"
    if path.startswith("/alertas") or path.startswith("/api/alerts"):
        return "alerts"
    if path.startswith("/configuracoes") or path.startswith("/api/settings") or path.startswith("/api/auth/allowed"):
        return "settings"
    return None


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/assets") or path in PUBLIC_AUTH_PATHS or path.startswith("/license/") or path.startswith("/api/alerts/inbound"):
            return await call_next(request)

        token = request.cookies.get(JWT_COOKIE_NAME)
        if not token and request.headers.get("authorization", "").lower().startswith("bearer "):
            token = request.headers.get("authorization", "")[7:].strip()

        if not token:
            if _wants_html(request):
                return RedirectResponse(url="/login", status_code=302)
            return JSONResponse(status_code=401, content={"detail": "Autenticação necessária."})

        try:
            payload = decode_access_token(token)
        except Exception as exc:
            if _wants_html(request):
                return RedirectResponse(url="/login", status_code=302)
            return JSONResponse(status_code=401, content={"detail": str(exc)})

        if payload.get("must_change_password") and path not in ("/change-password", "/api/auth/change-password", "/api/auth/logout", "/api/auth/me"):
            if _wants_html(request):
                return RedirectResponse(url="/change-password", status_code=302)
            return JSONResponse(status_code=403, content={"detail": "Troca de senha obrigatória antes de continuar.", "must_change_password": True})

        role = str(payload.get("role") or "viewer").lower()
        module = _module_for_path(path)
        if module and module not in ROLE_ACCESS.get(role, set()):
            return JSONResponse(status_code=403, content={"detail": f"Acesso negado para role {role} no módulo {module}."})

        request.state.user = payload
        response = await call_next(request)
        return response
