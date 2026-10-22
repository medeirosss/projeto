from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from app.license.license_service import license_service

router = APIRouter(tags=["license"])

LICENSE_PAGE = """
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Licença - Centric</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#0f172a;color:#f8fafc;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{width:min(720px,calc(100% - 32px));background:#1e293b;border:1px solid #334155;border-radius:18px;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
    h1{margin:0 0 8px}.muted{color:#cbd5e1}.box{background:#0f172a;border:1px solid #334155;border-radius:12px;padding:14px;margin:18px 0;white-space:pre-wrap}
    input{margin:12px 0;padding:10px;background:#0f172a;border:1px solid #475569;border-radius:10px;color:white;width:100%}
    button{background:#622A83;color:white;border:none;border-radius:10px;padding:12px 16px;font-weight:700;cursor:pointer}
  </style>
</head>
<body>
  <div class="card">
    <h1>Licenciamento Centric</h1>
    <p class="muted">Envie um arquivo <strong>license.json</strong> assinado para liberar a aplicação.</p>
    <div class="box" id="status">Carregando status...</div>
    <form id="form">
      <input type="file" name="file" accept=".json,application/json" required />
      <button type="submit">Atualizar licença</button>
    </form>
    <div class="box" id="result"></div>
  </div>
<script>
async function loadStatus(){
  const r = await fetch('/license/status');
  const j = await r.json();
  document.getElementById('status').textContent = JSON.stringify(j, null, 2);
}
document.getElementById('form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/license/upload', {method:'POST', body: fd});
  const j = await r.json();
  document.getElementById('result').textContent = JSON.stringify(j, null, 2);
  await loadStatus();
});
loadStatus();
</script>
</body>
</html>
"""


@router.get("/license", response_class=HTMLResponse)
async def license_page():
    return HTMLResponse(LICENSE_PAGE)


@router.get("/license/status")
async def license_status():
    return license_service.get_status()


@router.post("/license/upload")
async def license_upload(file: UploadFile = File(...)):
    content = await file.read()
    status = license_service.replace_license(content)
    if not status.get("valid"):
        return JSONResponse(status_code=400, content=status)
    public = dict(status)
    public.pop("raw_license", None)
    return public
