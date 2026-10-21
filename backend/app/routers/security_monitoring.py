from fastapi import APIRouter,HTTPException,Body
from app.services.security_monitoring_service import status,configure
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
