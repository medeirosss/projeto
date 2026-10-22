from fastapi import APIRouter, Body, HTTPException, Query
from app.repositories import exposure_repository as repo

router=APIRouter(prefix='/api/exposures',tags=['exposures'])

@router.get('')
def list_exposures(status:str|None=Query(None),severity:str|None=Query(None),search:str|None=Query(None),limit:int=Query(500,ge=1,le=1000)):
    return {'items':repo.list_findings(status=status,severity=severity,search=search,limit=limit),'summary':repo.summary()}

@router.get('/summary')
def exposure_summary(): return repo.summary()

@router.post('/rebuild')
def rebuild(): return repo.rebuild_all()

@router.patch('/{finding_uuid}')
def update_finding(finding_uuid:str,payload:dict=Body(...)):
    try:
        row=repo.set_status(finding_uuid,str(payload.get('status') or ''),payload.get('reason'))
        if not row: raise HTTPException(404,'Finding não encontrado.')
        return row
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
