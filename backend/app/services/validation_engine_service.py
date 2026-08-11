from __future__ import annotations
import socket
from typing import Any
from app.repositories.validation_repository import upsert_repository,upsert_task,list_repositories,list_tasks,get_task,create_execution,list_executions
from app.repositories.runner_repository import get_single_online_runner,create_runner_job

BUILTIN_TASKS=[
 {"task_key":"MAGI-NET-001","name":"RDP exposto","description":"Verifica se TCP/3389 está acessível a partir do Runner.","category":"Remote Access","platform":"Windows","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":3389,"finding_when":"open"},"remediation":"Restrinja RDP por firewall/VPN, limite origens autorizadas e mantenha NLA/MFA conforme a política do ambiente."},
 {"task_key":"MAGI-NET-002","name":"SMB exposto","description":"Verifica se TCP/445 está acessível a partir do Runner.","category":"File Sharing","platform":"Windows","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":445,"finding_when":"open"},"remediation":"Restrinja SMB às redes administrativas necessárias; bloqueie TCP/445 entre segmentos que não precisam compartilhar arquivos."},
 {"task_key":"MAGI-NET-003","name":"WinRM HTTP exposto","description":"Verifica se TCP/5985 está acessível a partir do Runner.","category":"Remote Management","platform":"Windows","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":5985,"finding_when":"open"},"remediation":"Restrinja WinRM às redes de administração e prefira HTTPS/5986 quando aplicável."},
 {"task_key":"MAGI-NET-004","name":"WinRM HTTPS acessível","description":"Identifica exposição do serviço WinRM HTTPS TCP/5986.","category":"Remote Management","platform":"Windows","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":5986,"finding_when":"open"},"remediation":"Mantenha o acesso restrito a origens administrativas autorizadas e valide certificados e autenticação."},
 {"task_key":"MAGI-NET-005","name":"SSH exposto","description":"Verifica se TCP/22 está acessível a partir do Runner.","category":"Remote Access","platform":"Linux/Network","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":22,"finding_when":"open"},"remediation":"Restrinja SSH por ACL/firewall, use autenticação forte e desabilite métodos não necessários."},
 {"task_key":"MAGI-NET-006","name":"Telnet exposto","description":"Verifica se TCP/23 está acessível; Telnet transmite sessão sem proteção criptográfica adequada.","category":"Legacy Protocol","platform":"Any","executor":"security_check","impact":"low","detection":{"type":"tcp_port","port":23,"finding_when":"open"},"remediation":"Desabilite Telnet e migre a administração para SSH ou outro protocolo seguro."},
]

def sync_repositories()->dict[str,Any]:
    upsert_repository({"repository_key":"magi","name":"MAGI Security Checks","provider":"magi","description":"Checks defensivos nativos do MAGI.","available":True,"metadata":{"execution":"native","version":"4.0"}})
    upsert_repository({"repository_key":"atomic","name":"Atomic Red Team","provider":"atomic_red_team","description":"Catálogo Atomic Red Team já integrado ao MAGI.","available":True,"metadata":{"execution":"atomic"}})
    upsert_repository({"repository_key":"nuclei","name":"Nuclei Templates","provider":"nuclei","description":"Provider preparado para integração de templates Nuclei em sprint posterior.","available":False,"metadata":{"execution":"planned","reason":"binary/template sync not enabled in 4.0"}})
    for task in BUILTIN_TASKS: upsert_task({"repository_key":"magi",**task,"approved":True,"enabled":True,"requires_admin":False})
    return {"success":True,"repositories":list_repositories(),"magi_tasks":len(BUILTIN_TASKS)}

def repository_summary():
    repos=list_repositories(); tasks=list_tasks(limit=1000)
    return {"success":True,"repositories":repos,"summary":{"repositories":len(repos),"available_repositories":sum(1 for r in repos if r.get('available')),"tasks":len(tasks),"enabled_tasks":sum(1 for t in tasks if t.get('enabled'))}}

def task_catalog(repository_key=None,search=None,category=None): return {"success":True,"tasks":list_tasks(repository_key,search,category)}

def plan_task(task_id:int,target:str)->dict[str,Any]:
    target=(target or '').strip()
    if not target: raise ValueError('Target é obrigatório.')
    task=get_task(task_id)
    if not task: raise ValueError('Tarefa não encontrada.')
    if not task.get('enabled'): raise ValueError('Tarefa desabilitada pelo administrador.')
    if not task.get('approved'): raise ValueError('Tarefa ainda não aprovada pelo administrador.')
    runner=get_single_online_runner()
    if not runner: raise ValueError('Nenhum Runner online disponível.')
    detection=task.get('detection') or {}
    plan={"task_id":task_id,"task_key":task['task_key'],"repository":task['repository_key'],"target":target,"runner_id":runner['runner_id'],"executor":task['executor'],"impact":task.get('impact'),"requires_admin":bool(task.get('requires_admin')),"detection":detection,"remediation":task.get('remediation'),"ready":True}
    return {"success":True,"plan":plan,"task":task}

def execute_task(task_id:int,target:str,requested_by:str='ui'):
    prepared=plan_task(task_id,target); plan=prepared['plan']; task=prepared['task']
    payload={"executor":task['executor'],"validation_type":"security_check","task_id":task_id,"task_key":task['task_key'],"repository_key":task['repository_key'],"target":target,"detection":task.get('detection') or {},"impact":task.get('impact'),"remediation":task.get('remediation')}
    job=create_runner_job(plan['runner_id'],'security_check',target,payload)
    execution=create_execution(task,plan['runner_id'],job['id'],target,requested_by,plan)
    return {"success":True,"plan":plan,"runner_job":job,"execution":execution}

def execution_history(): return {"success":True,"executions":list_executions()}
