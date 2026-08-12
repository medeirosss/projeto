from __future__ import annotations
import socket
from typing import Any
from app.repositories.validation_repository import upsert_repository,upsert_task,list_repositories,list_tasks,get_task,create_execution,list_executions,get_execution
from app.repositories.runner_repository import get_single_online_runner,create_runner_job
from app.repositories.atomic_repository import list_atomic_executions, get_atomic_execution_by_id

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

def _iso_sort_value(value):
    if value is None:
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _atomic_confirmation_status(row:dict):
    evidence=row.get("evidence") or {}
    meta=evidence.get("metadata") or {}
    explicit=evidence.get("confirmation_status") or meta.get("confirmation_status")
    if explicit:
        return explicit
    status=str(row.get("status") or "").lower()
    if status in {"failed","error","timeout","blocked"}:
        return "error"
    if bool(row.get("executed_real_test")) and status=="success":
        return "executed_unverified"
    return None

def _atomic_confirmation_message(row:dict):
    evidence=row.get("evidence") or {}
    meta=evidence.get("metadata") or {}
    confirmation=_atomic_confirmation_status(row)
    scope=evidence.get("execution_scope") or meta.get("execution_scope")
    requested=evidence.get("requested_target") or meta.get("requested_target") or row.get("target_host")
    if confirmation=="executed_unverified":
        if scope=="runner_local":
            return f"Atomic executado no Runner; efeito não confirmado no target solicitado {requested or '--'}."
        return "Atomic executado; efeito pós-execução ainda não confirmado por evidência independente."
    if confirmation=="confirmed":
        return "Efeito da técnica confirmado por evidência pós-execução."
    if confirmation=="not_confirmed":
        return "Comando executado, mas o efeito esperado não foi confirmado."
    if confirmation=="error":
        return row.get("error_message") or "Execução Atomic falhou ou foi interrompida."
    return None

def _normalize_atomic(row:dict):
    return {
        "source":"atomic", "source_label":"Atomic Red Team", "id":row.get("id"),
        "execution_uuid":row.get("execution_uuid"), "technique_id":row.get("technique_id"),
        "atomic_test_number":row.get("atomic_test_number"), "task_key":row.get("technique_id"),
        "task_name":row.get("atomic_name"), "executor":row.get("executor_name") or "atomic",
        "runner_id":row.get("runner_id"), "runner_job_id":row.get("runner_job_id"),
        "target":row.get("target_host"), "status":row.get("status"),
        "finding_status":_atomic_confirmation_status(row),
        "finding_message":_atomic_confirmation_message(row),
        "requested_by":row.get("requested_by"), "approved_by":row.get("approved_by"),
        "created_at":row.get("created_at"), "started_at":row.get("started_at"), "finished_at":row.get("finished_at"),
        "duration_seconds":row.get("duration_seconds"), "executed_real_test":bool(row.get("executed_real_test")),
        "error":row.get("error_message") or row.get("block_reason"), "evidence":row.get("evidence") or {},
        "remediation":None,
    }


def _normalize_magi(row:dict):
    duration=None
    if row.get("started_at") and row.get("finished_at"):
        try: duration=int((row["finished_at"]-row["started_at"]).total_seconds())
        except Exception: duration=None
    return {
        "source":"magi", "source_label":"MAGI", "id":row.get("id"),
        "execution_uuid":row.get("execution_uuid"), "technique_id":None, "atomic_test_number":None,
        "task_key":row.get("task_key"), "task_name":row.get("task_name") or row.get("task_key"),
        "executor":row.get("executor") or "security_check", "runner_id":row.get("runner_id"),
        "runner_job_id":row.get("runner_job_id"), "target":row.get("target"), "status":row.get("status"),
        "finding_status":row.get("finding_status"), "finding_message":row.get("finding_message"),
        "requested_by":row.get("requested_by"), "approved_by":None, "created_at":row.get("created_at"),
        "started_at":row.get("started_at"), "finished_at":row.get("finished_at"), "duration_seconds":duration,
        "executed_real_test":True if row.get("finished_at") else False, "error":row.get("error"),
        "evidence":row.get("evidence") or {}, "remediation":row.get("remediation"),
    }


def unified_execution_history(limit=100, search=None, technique_id=None, runner_id=None, status=None, requested_by=None, date_from=None, date_to=None, source=None):
    fetch_limit=max(200, min(int(limit or 100)*5, 1000))
    atomic=list_atomic_executions(limit=fetch_limit, offset=0).get("items", [])
    magi=list_executions(limit=fetch_limit)
    rows=[_normalize_atomic(x) for x in atomic]+[_normalize_magi(x) for x in magi]
    def match(row):
        if source and row.get("source") != source: return False
        if status and str(row.get("status") or "").lower() != str(status).lower(): return False
        if runner_id and str(runner_id).lower() not in str(row.get("runner_id") or "").lower(): return False
        if requested_by and str(requested_by).lower() not in str(row.get("requested_by") or "").lower(): return False
        if technique_id:
            needle=str(technique_id).lower()
            if needle not in str(row.get("technique_id") or "").lower() and needle not in str(row.get("task_key") or "").lower(): return False
        hay=" ".join(str(row.get(k) or "") for k in ["execution_uuid","technique_id","task_key","task_name","runner_id","target","requested_by","finding_message"]).lower()
        if search and str(search).lower() not in hay: return False
        created=_iso_sort_value(row.get("created_at"))[:10]
        if date_from and created and created < str(date_from): return False
        if date_to and created and created > str(date_to): return False
        return True
    rows=[r for r in rows if match(r)]
    rows.sort(key=lambda r:(_iso_sort_value(r.get("created_at")), int(r.get("id") or 0)), reverse=True)
    total=len(rows)
    return {"success":True,"executions":rows[:max(1,min(int(limit or 100),500))],"total":total}


def execution_detail(source:str, execution_id:int):
    if source == "atomic":
        row=get_atomic_execution_by_id(execution_id)
        if not row: raise ValueError("Atomic execution not found")
        normalized=_normalize_atomic(row)
        normalized["raw"] = row
        return {"success":True,"execution":normalized}
    if source == "magi":
        row=get_execution(execution_id)
        if not row: raise ValueError("MAGI execution not found")
        normalized=_normalize_magi(row)
        normalized["raw"] = row
        return {"success":True,"execution":normalized}
    raise ValueError("Unknown execution source")


def execution_history(): return {"success":True,"executions":list_executions()}
