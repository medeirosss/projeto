from __future__ import annotations
from fastapi import APIRouter,Body,HTTPException,Request
from app.services.validation_engine_service import sync_repositories,repository_summary,task_catalog,plan_task,execute_task,execution_history
router=APIRouter(prefix='/api/repositories',tags=['repositories'])

@router.post('/sync')
def sync(): return sync_repositories()
@router.get('/summary')
def summary(): return repository_summary()
@router.get('/tasks')
def tasks(repository_key:str|None=None,search:str|None=None,category:str|None=None): return task_catalog(repository_key,search,category)
@router.post('/tasks/{task_id}/plan')
def plan(task_id:int,payload:dict=Body(...)):
    try:return plan_task(task_id,payload.get('target'))
    except Exception as exc: raise HTTPException(400,str(exc))
@router.post('/tasks/{task_id}/execute')
def execute(task_id:int,request:Request,payload:dict=Body(...)):
    try:
        u=getattr(request.state,'user',{}) or {}; requested=u.get('sub') or u.get('username') or 'ui'
        return execute_task(task_id,payload.get('target'),requested)
    except Exception as exc: raise HTTPException(400,str(exc))
@router.get('/executions')
def executions(): return execution_history()
