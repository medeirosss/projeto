from fastapi import APIRouter,HTTPException,Body
from app.services.security_monitoring_service import status,configure,verify_now,update_alert
router=APIRouter(prefix='/api/security-monitoring',tags=['security-monitoring'])

@router.get('/campaigns/{campaign_uuid}')
def get_monitor(campaign_uuid:str):
    try:return status(campaign_uuid)
    except ValueError as exc:raise HTTPException(404,str(exc))

@router.post('/campaigns/{campaign_uuid}')
def set_monitor(campaign_uuid:str,payload:dict=Body(...)):
    try:
        if not isinstance(payload.get('enabled'),bool):raise ValueError('enabled deve ser booleano')
        return configure(campaign_uuid,payload['enabled'])
    except ValueError as exc:raise HTTPException(400,str(exc))

@router.post('/campaigns/{campaign_uuid}/verify-now')
def verify_monitor_now(campaign_uuid:str):
    try:return verify_now(campaign_uuid)
    except ValueError as exc:raise HTTPException(409,str(exc))

@router.post('/campaigns/{campaign_uuid}/alerts/{alert_id}/{action}')
def manage_monitor_alert(campaign_uuid:str,alert_id:int,action:str):
    try:return update_alert(campaign_uuid,alert_id,action)
    except ValueError as exc:raise HTTPException(409,str(exc))
