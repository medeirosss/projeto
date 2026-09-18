from fastapi import APIRouter, Body, HTTPException
from app.services.attack_knowledge_service import knowledge_status, knowledge_catalog, import_snapshot, sync_history
router=APIRouter(prefix='/api/attack-knowledge',tags=['attack-knowledge'])
@router.get('/status')
def status(): return knowledge_status()
@router.get('/catalog')
def catalog(category:str|None=None,impact:str|None=None,status:str='active'): return knowledge_catalog(category,impact,status)
@router.get('/history')
def history(limit:int=50): return sync_history(max(1,min(limit,200)))
@router.post('/import')
def import_full_snapshot(payload:dict=Body(...)):
    try: return import_snapshot(payload,'offline_update')
    except Exception as exc: raise HTTPException(400,str(exc))
