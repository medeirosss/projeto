from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body, File, HTTPException, Request, UploadFile

from app.services.action_service import (
    decide_execution_mode,
    execute_alert_action,
    execute_manual_action,
    fetch_security_alerts,
    get_alert_summary,
    get_known_targets,
    get_last_alert,
    get_listener_info,
    list_scripts,
    normalize_inbound_alert,
    save_last_alert,
)
from app.services.credentials_service import delete_credential, list_credentials, save_credential
from app.services.scripts_service import delete_script, save_script_from_upload
from app.services.settings_service import get_settings_data
from app.repositories.executions_repository import list_playbook_executions
from app.services.alert_service import create_alert_from_inbound
from app.services.webhook_security_service import validate_inbound_webhook_request

router = APIRouter(prefix='/api/actions', tags=['actions'])


@router.get('/listener-info')
async def api_action_listener_info():
    return get_listener_info()


@router.get('/scripts')
async def api_action_scripts():
    return {'scripts': list_scripts()}


@router.post('/scripts/upload')
async def api_action_scripts_upload(file: UploadFile = File(...)):
    filename = Path(file.filename or '').name
    if not filename:
        raise HTTPException(status_code=400, detail='Arquivo inválido.')
    suffix = Path(filename).suffix.lower()
    if suffix not in {'.ps1', '.sh'}:
        raise HTTPException(status_code=400, detail='Somente arquivos .ps1 e .sh são suportados.')
    data = await file.read()
    try:
        content = data.decode('utf-8')
    except UnicodeDecodeError:
        content = data.decode('latin-1')
    try:
        script = save_script_from_upload(filename, content)
        return {'success': True, 'script': script}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete('/scripts/{script_name}')
async def api_action_scripts_delete(script_name: str):
    ok = delete_script(script_name)
    if not ok:
        raise HTTPException(status_code=404, detail='Script não encontrado.')
    return {'success': True}


@router.get('/credentials')
async def api_action_credentials():
    return {'credentials': list_credentials()}


@router.post('/credentials')
async def api_action_credentials_save(payload: Dict[str, Any] = Body(...)):
    try:
        return {'credential': save_credential(payload or {})}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete('/credentials/{cred_id}')
async def api_action_credentials_delete(cred_id: str):
    if not delete_credential(cred_id):
        raise HTTPException(status_code=404, detail='Credencial não encontrada.')
    return {'success': True}


@router.get('/targets')
async def api_action_targets():
    return get_known_targets()


@router.get('/alerts')
async def api_action_alerts():
    return {'summary': get_alert_summary(), 'alerts': fetch_security_alerts()}


@router.post('/inbound-alert')
async def api_inbound_alert(request: Request, payload: Dict[str, Any] = Body(...)):
    validation = validate_inbound_webhook_request(request)
    normalized = normalize_inbound_alert(payload or {})
    normalized['received_from_ip'] = validation.get('client_ip')
    normalized['webhook_validation'] = validation.get('reason')
    save_last_alert(normalized)
    stored = create_alert_from_inbound(normalized)
    return {'success': True, 'alert': stored, 'webhook': validation}


@router.get('/last-alert')
async def api_action_last_alert():
    return {'alert': get_last_alert()}


@router.post('/plan')
async def api_action_plan(payload: Dict[str, Any] = Body(...)):
    settings = get_settings_data()
    cidrs = settings.get('uem', {}).get('ip_scope', {}).get('cidrs', [])
    ip_value = str(payload.get('ip') or payload.get('source_ip') or '').strip()
    return decide_execution_mode(ip_value, cidrs)


@router.post('/execute/manual')
async def api_action_execute_manual(request: Request, payload: Dict[str, Any] = Body(...)):
    settings = get_settings_data()
    cidrs = settings.get('uem', {}).get('ip_scope', {}).get('cidrs', [])
    try:
        user = getattr(request.state, 'user', {}) or {}
        executed_by = str(user.get('sub') or user.get('username') or 'system')
        return execute_manual_action(payload or {}, cidrs, executed_by=executed_by)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post('/execute/alert')
async def api_action_execute_alert(request: Request, payload: Dict[str, Any] = Body(...)):
    settings = get_settings_data()
    cidrs = settings.get('uem', {}).get('ip_scope', {}).get('cidrs', [])
    try:
        user = getattr(request.state, 'user', {}) or {}
        executed_by = str(user.get('sub') or user.get('username') or 'system')
        return execute_alert_action(payload or {}, cidrs, executed_by=executed_by)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get('/executions')
async def api_action_executions(limit: int = 100):
    return {'executions': list_playbook_executions(limit=limit)}
