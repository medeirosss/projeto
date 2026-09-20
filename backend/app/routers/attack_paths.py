from fastapi import APIRouter,Body,HTTPException,Request
from app.services.attack_path_service import list_runs,create_run,get_run,telemetry,ingest_relay,create_from_campaign
router=APIRouter(prefix='/api/attack-simulator/attack-paths',tags=['attack-paths'])
def _user(req):
    u=getattr(req.state,'user',{}) or {}; return u.get('sub') or u.get('username') or 'ui'
@router.get('')
def ls(): return {'success':True,'items':list_runs()}
@router.post('')
def create(req:Request,payload:dict=Body(default={})):
    try:return {'success':True,'path':create_run(payload,_user(req))}
    except Exception as e:raise HTTPException(400,str(e))
@router.get('/{path_uuid}')
def detail(path_uuid:str):
    try:return {'success':True,**get_run(path_uuid)}
    except Exception as e:raise HTTPException(404,str(e))
@router.post('/{path_uuid}/telemetry')
def event(path_uuid:str,payload:dict=Body(...)):
    try:return telemetry(path_uuid,payload)
    except Exception as e:raise HTTPException(400,str(e))
@router.post('/{path_uuid}/telemetry/relay')
def relay(path_uuid:str,payload:dict=Body(...)):
    try:return ingest_relay(path_uuid,payload)
    except Exception as e:raise HTTPException(400,str(e))

@router.post('/from-campaign/{campaign_uuid}')
def from_campaign(campaign_uuid:str,req:Request):
    try:return {'success':True,**create_from_campaign(campaign_uuid,_user(req))}
    except Exception as e:raise HTTPException(400,str(e))
