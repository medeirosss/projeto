from __future__ import annotations
from fastapi import APIRouter, Body, HTTPException, Request
from app.services.attack_campaign_service import create_attack_campaign,campaign_list,campaign_detail,campaign_pause,campaign_resume,campaign_delete,campaign_update,campaign_next_cycle_now
router=APIRouter(prefix='/api/attack-simulator/campaigns',tags=['attack-campaigns'])

def _user(req:Request):
    u=getattr(req.state,'user',{}) or {}; return u.get('sub') or u.get('username') or 'ui'

@router.get('')
def list_all(): return campaign_list()
@router.post('')
def create(req:Request,payload:dict=Body(...)):
    try:return create_attack_campaign(payload,_user(req))
    except Exception as exc:raise HTTPException(400,str(exc))
@router.get('/{campaign_uuid}')
def detail(campaign_uuid:str):
    try:return campaign_detail(campaign_uuid)
    except Exception as exc:raise HTTPException(404,str(exc))
@router.post('/{campaign_uuid}/pause')
def pause(campaign_uuid:str):
    try:return campaign_pause(campaign_uuid)
    except Exception as exc:raise HTTPException(400,str(exc))
@router.post('/{campaign_uuid}/resume')
def resume(campaign_uuid:str):
    try:return campaign_resume(campaign_uuid)
    except Exception as exc:raise HTTPException(400,str(exc))
@router.patch('/{campaign_uuid}')
def adjust(campaign_uuid:str,payload:dict=Body(...)):
    try:return campaign_update(campaign_uuid,payload)
    except Exception as exc:raise HTTPException(400,str(exc))
@router.post('/{campaign_uuid}/next-cycle')
def next_cycle(campaign_uuid:str):
    try:return campaign_next_cycle_now(campaign_uuid)
    except Exception as exc:raise HTTPException(400,str(exc))
@router.delete('/{campaign_uuid}')
def delete(campaign_uuid:str): return campaign_delete(campaign_uuid)
