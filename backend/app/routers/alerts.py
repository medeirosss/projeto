from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException

from app.services.alert_service import (
    alert_summary,
    get_alert_by_id,
    list_open_alerts,
    list_resolved_alerts,
    register_execution_result,
    update_alert_status,
    create_alert_from_payload,  # <-- IMPORTANTE
)

router = APIRouter(prefix='/api/alerts', tags=['alerts'])


@router.get('')
async def api_alerts_list():
    return {'summary': alert_summary(), 'alerts': list_open_alerts()}


@router.get('/resolved')
async def api_alerts_resolved():
    return {'alerts': list_resolved_alerts()}


# 🔥 NOVO ENDPOINT INBOUND (ANTES DO {alert_id})
@router.post('/inbound')
async def api_alert_inbound(payload: Dict[str, Any] = Body(...)):
    try:
        alert = create_alert_from_payload(payload)
        return {'success': True, 'alert': alert}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get('/{alert_id}')
async def api_alert_by_id(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail='Alerta não encontrado.')
    return {'alert': alert}


@router.post('/{alert_id}/status')
async def api_alert_status(alert_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        alert = update_alert_status(
            alert_id,
            int(payload.get('status') or 0),
            str(payload.get('resolution_type') or ''),
            str(payload.get('resolved_by') or ''),
            str(payload.get('message') or ''),
        )
        return {'success': True, 'alert': alert}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post('/{alert_id}/execution-result')
async def api_alert_execution_result(alert_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        alert = register_execution_result(
            alert_id,
            bool(payload.get('success')),
            str(payload.get('message') or ''),
            str(payload.get('resolution_type') or 'playbook'),
        )
        return {'success': True, 'alert': alert}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))