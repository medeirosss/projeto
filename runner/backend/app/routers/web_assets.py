from fastapi import APIRouter,Body,HTTPException
from app.services.web_asset_service import list_assets,create_asset,rescan
router=APIRouter(prefix='/api/web-assets',tags=['web-assets'])
@router.get('')
def api_list(): return {'items':list_assets()}
@router.post('')
def api_create(payload:dict=Body(...)):
    try:return create_asset(payload.get('name') or '',payload.get('url') or '')
    except Exception as e: raise HTTPException(400,str(e))
@router.post('/{web_uuid}/rescan')
def api_rescan(web_uuid:str):
    try:return rescan(web_uuid)
    except Exception as e: raise HTTPException(400,str(e))
