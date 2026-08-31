from __future__ import annotations

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.license.license_service import license_service
from app.license.module_registry import is_public_path, module_for_path

LICENSE_ERROR_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Licença inválida</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#111827;color:#f9fafb;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{max-width:620px;background:#1f2937;border:1px solid #374151;border-radius:18px;padding:32px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
    h1{margin:0 0 12px;font-size:26px}.msg{color:#d1d5db;line-height:1.5}.actions{margin-top:22px;display:flex;gap:12px;flex-wrap:wrap}
    a{color:white;background:#622A83;text-decoration:none;padding:11px 16px;border-radius:10px;font-weight:600}
    code{background:#111827;border-radius:6px;padding:2px 6px;color:#e5e7eb}
  </style>
</head>
<body>
  <div class="card">
    <h1>Licença inválida ou expirada</h1>
    <p class="msg">A aplicação está bloqueada. Entre em contato com o suporte.</p>
    <p class="msg">Somente os endpoints <code>/license/status</code>, <code>/license/upload</code> e <code>/health</code> permanecem disponíveis.</p>
    <div class="actions"><a href="/license">Atualizar licença</a></div>
  </div>
</body>
</html>
"""


class LicenseMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if is_public_path(path):
            return await call_next(request)

        module = module_for_path(path)
        if not license_service.is_valid():
            if "text/html" in request.headers.get("accept", ""):
                return HTMLResponse(LICENSE_ERROR_HTML, status_code=403)
            return JSONResponse(
                status_code=403,
                content={"detail": "Licença inválida ou expirada. Entre em contato com o suporte."},
            )

        if not license_service.is_module_allowed(module):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Módulo não licenciado: {module or 'unknown'}."},
            )

        return await call_next(request)
