from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, time as dtime
from zoneinfo import ZoneInfo
from typing import Any
from sqlalchemy import text

from app.repositories.attack_campaign_repository import create_campaign, list_campaigns, get_campaign, set_campaign_status, delete_campaign, db_session
from app.repositories.runner_repository import create_runner_job, get_single_online_runner, is_runner_queue_paused
from app.repositories.validation_repository import list_tasks, create_execution
from app.repositories.target_repository import upsert_discovered_target

BRANCH_POLICY = [10, 5, 3, 0]


def _campaign_now() -> datetime:
    """Return MAGI Campaign wall-clock time as a naive datetime.

    Campaign scheduling fields are stored as TIMESTAMP/TIME without timezone and
    originate from the operator UI. Always compare them against the configured
    MAGI timezone instead of UTC.
    """
    tz_name = os.getenv("MAGI_TIMEZONE") or os.getenv("TZ") or "America/Sao_Paulo"
    try:
        return datetime.now(ZoneInfo(tz_name)).replace(tzinfo=None)
    except Exception:
        return datetime.now(ZoneInfo("America/Sao_Paulo")).replace(tzinfo=None)


def _parse_dt(v: Any) -> datetime:
    if isinstance(v, datetime): return v
    return datetime.fromisoformat(str(v).replace('Z','+00:00')).replace(tzinfo=None)


def _validate_campaign(data: dict[str, Any]) -> dict[str, Any]:
    name=str(data.get('name') or '').strip()
    if not name: raise ValueError('Nome da Campaign é obrigatório.')
    seeds=[str(x).strip() for x in (data.get('initial_seeds') or []) if str(x).strip()]
    if not seeds or len(seeds)>3: raise ValueError('Informe de 1 a 3 Hosts A iniciais.')
    scopes=[str(x).strip() for x in (data.get('scope_cidrs') or []) if str(x).strip()]
    if not scopes: raise ValueError('Ao menos uma rede CIDR é obrigatória.')
    total=0
    for raw in scopes:
        net=ipaddress.ip_network(raw, strict=False)
        total += max(0, net.num_addresses-2 if net.version==4 and net.prefixlen<31 else net.num_addresses)
        if net.num_addresses > 4096: raise ValueError('Na 5.2 cada bloco da Campaign pode ter no máximo 4096 endereços.')
    start=_parse_dt(data.get('start_at')); end=_parse_dt(data.get('end_at'))
    if end <= start: raise ValueError('Data/hora final deve ser posterior ao início.')
    interval=max(15,int(data.get('cycle_interval_minutes') or 15))
    timeout=max(5,min(15,int(data.get('cycle_timeout_minutes') or 15)))
    recurrence=data.get('recurrence_days')
    if recurrence in ('',None): recurrence=None
    elif int(recurrence)<1: raise ValueError('Recorrência deve ser de pelo menos 1 dia.')
    vectors=[v for v in (data.get('enabled_vectors') or ['winrm','smb','ssh','snmp_v2c']) if v in {'winrm','smb','ssh','snmp_v2c'}]
    if not vectors: raise ValueError('Selecione ao menos um vetor da Campaign.')
    return {**data,'name':name,'initial_seeds':seeds,'scope_cidrs':scopes,'start_at':start,'end_at':end,'enabled_vectors':vectors,
            'cycle_interval_minutes':interval,'cycle_timeout_minutes':timeout,'recurrence_days':int(recurrence) if recurrence else None,
            'max_seeds_per_cycle':3,'branch_policy':BRANCH_POLICY,'max_paths_per_cycle':max(10,min(100,int(data.get('max_paths_per_cycle') or 60))),
            'max_outstanding_jobs':max(1,min(10,int(data.get('max_outstanding_jobs') or 5))),'snapshot_retention':10}


def create_attack_campaign(data: dict[str, Any], requested_by: str) -> dict[str, Any]:
    payload=_validate_campaign(data)
    row=create_campaign(payload, requested_by)
    return {'success':True,'campaign':row,'policy':{'branch_policy':BRANCH_POLICY,'snapshot_retention':10,'cycle_timeout_max_minutes':15,'multi_protocol':True,'vectors':payload.get('enabled_vectors')}}


def campaign_list() -> dict[str, Any]: return {'success':True,'campaigns':list_campaigns()}

def _attack_path_payload(c: dict[str, Any]) -> dict[str, Any]:
    """Build a campaign-local attack graph from the latest execution only."""
    executions=c.get('executions') or []
    ex=executions[0] if executions else {}
    paths=c.get('paths') or []
    assets=c.get('assets') or []
    cycles=c.get('cycles') or []
    asset_by_addr={str(a.get('address')):a for a in assets if a.get('address')}

    def status_kind(p):
        st=str(p.get('status') or '').lower()
        ev=p.get('evidence') or {}
        result=str(p.get('result') or '')
        if st=='confirmed' or bool(ev.get('access_confirmed')): return 'ACCESS'
        if p.get('relation_type')=='discovery' and (ev.get('snmp_confirmed') or ev.get('confirmation_status')=='snmp_confirmed'): return 'SNMP'
        blob=(st+' '+result+' '+__import__('json').dumps(ev,default=str)).lower()
        if 'authentication_failed' in blob or 'auth_failed' in blob: return 'AUTHENTICATION_FAILED'
        if 'transport_failed' in blob or 'unreachable' in blob: return 'TRANSPORT_FAILED'
        if 'service' in blob and ('unavailable' in blob or 'closed' in blob): return 'SERVICE_UNAVAILABLE'
        if p.get('relation_type')=='discovery': return 'DISCOVERY'
        return 'BARRIER' if st in ('failed','error','timeout','cancelled','not_confirmed') else 'DISCOVERY'

    addresses=set(asset_by_addr)
    for p in paths:
        if p.get('origin_address'): addresses.add(str(p['origin_address']))
        if p.get('target_address'): addresses.add(str(p['target_address']))
    nodes=[{'id':'runner','label':'MAGI Runner','type':'runner','address':None,'access_confirmed':True}]
    for addr in sorted(addresses):
        a=asset_by_addr.get(addr,{})
        nodes.append({'id':addr,'label':a.get('hostname') or addr,'address':addr,'type':'asset',
                      'state':a.get('state'),'access_confirmed':bool(a.get('access_confirmed')),
                      'access_method':a.get('access_method'),'first_seen_at':a.get('first_seen_at'),'last_seen_at':a.get('last_seen_at')})
    edges=[]; evidence=[]; barriers=[]
    for p in reversed(paths):  # chronological graph/evidence
        ev=p.get('evidence') or {}; kind=status_kind(p)
        origin=str(p.get('origin_address') or 'runner'); target=str(p.get('target_address') or '')
        protocol=p.get('protocol') or ev.get('protocol') or ev.get('access_method')
        display_protocol='Discovery / ICMP' if str(protocol).lower() in ('preflight','icmp') else protocol
        blob=(str(p.get('status') or '')+' '+str(p.get('result') or '')+' '+__import__('json').dumps(ev,default=str)).lower()
        reason=ev.get('barrier_reason') or ev.get('reason') or ev.get('error') or ev.get('snmp_error')
        if not reason:
            if 'authentication_failed' in blob or 'auth_failed' in blob: reason='Credential rejected by the destination.'
            elif 'trustedhosts_failed' in blob: reason='MAGI could not apply or restore the temporary WinRM TrustedHosts configuration.'
            elif 'transport_failed' in blob or 'unreachable' in blob: reason='Transport to the destination could not be established.'
            elif 'service_unavailable' in blob or ('service' in blob and ('unavailable' in blob or 'closed' in blob)): reason='Required service is unavailable on the destination.'
            elif 'timeout' in blob: reason='The WinRM validation exceeded the allowed execution time.'
            elif 'runner_dependency_missing' in blob: reason='Runner dependency required for this test is missing.'
            elif str(p.get('result') or '')=='discovery_not_confirmed': reason='No ICMP Echo Reply received from the target IP.'
            elif str(p.get('status') or '').lower() in ('failed','error','cancelled','not_confirmed'): reason=str(p.get('result') or 'Execution did not confirm the path.')
        item={'path_id':p.get('id'),'cycle_id':p.get('cycle_id'),'hop':p.get('hop'),'origin':origin,'target':target,
              'protocol':display_protocol,'raw_protocol':protocol,'reason':reason,'relation_type':p.get('relation_type'),'status':p.get('status'),'kind':kind,
              'runner_job_id':p.get('runner_job_id'),'credential_ref':ev.get('credential_id') or ev.get('credential_ref'),
              'result':p.get('result'),'evidence':ev,'started_at':p.get('started_at'),'finished_at':p.get('finished_at')}
        evidence.append(item)
        if target and str(p.get('result') or '')!='discovery_not_confirmed':
            edges.append(item)
        if kind in ('AUTHENTICATION_FAILED','TRANSPORT_FAILED','SERVICE_UNAVAILABLE','BARRIER'):
            barriers.append(item)
    confirmed=[e for e in edges if e['kind']=='ACCESS']
    snmp=[e for e in edges if e['kind']=='SNMP']
    max_hop=max([int(e.get('hop') or 0) for e in confirmed],default=0)
    summary={'ips_evaluated':len({e['target'] for e in edges if e.get('target')}),
             'hosts_known':len(assets),'access_confirmed':len({e['target'] for e in confirmed}),
             'seeds_confirmed':len({e['target'] for e in confirmed}),
             'max_hop':max_hop,'snmp_discovered':len({e['target'] for e in snmp}),
             'barriers':len(barriers),'cycles':len(cycles)}
    protocols={}
    for e in confirmed:
        k=str(e.get('protocol') or 'unknown').upper(); protocols[k]=protocols.get(k,0)+1
    summary['confirmed_by_protocol']=protocols
    stop_reason=(cycles[0].get('stop_reason') if cycles else None) or ex.get('status')
    summary['stop_reason']=stop_reason
    return {'campaign_uuid':c.get('campaign_uuid'),'campaign_name':c.get('name'),
            'execution_id':ex.get('id'),'execution_number':ex.get('execution_number'),
            'summary':summary,'nodes':nodes,'edges':edges,'barriers':barriers,'evidence':evidence}


def campaign_attack_path(uuid: str) -> dict[str, Any]:
    c=get_campaign(uuid)
    if not c: raise ValueError('Campaign não encontrada.')
    return {'success':True,'attack_path':_attack_path_payload(c)}

def campaign_detail(uuid: str) -> dict[str, Any]:
    row=get_campaign(uuid)
    if not row: raise ValueError('Campaign não encontrada.')
    return {'success':True,'campaign':row}
def _cancel_campaign_jobs(db, campaign_id: int, reason: str) -> dict[str, int]:
    """Cancel every outstanding Runner job owned by a Campaign execution.

    This is deliberately idempotent. A job already completed is left untouched;
    pending/running jobs are terminally marked cancelled so they cannot be
    reclaimed by the Runner after the operator pauses the Campaign.
    """
    now=datetime.utcnow()
    job_ids=[r[0] for r in db.execute(text("""
      SELECT DISTINCT p.runner_job_id
      FROM attack_campaign_paths p
      JOIN attack_campaign_executions e ON e.id=p.execution_id
      WHERE e.campaign_id=:c AND p.runner_job_id IS NOT NULL
        AND p.status IN ('queued','running')
    """),{'c':campaign_id}).all()]
    cancelled_jobs=0
    if job_ids:
        cancelled_jobs=db.execute(text("""
          UPDATE runner_jobs SET status='cancelled',error=:reason,finished_at=:now
          WHERE id = ANY(:ids) AND status IN ('pending','running')
        """),{'ids':job_ids,'reason':reason,'now':now}).rowcount or 0
    cancelled_paths=db.execute(text("""
      UPDATE attack_campaign_paths p
      SET status='cancelled',result='campaign_cancelled',finished_at=:now,
          evidence=COALESCE(p.evidence,'{}'::jsonb) || CAST(:ev AS JSONB)
      FROM attack_campaign_executions e
      WHERE p.execution_id=e.id AND e.campaign_id=:c
        AND p.status IN ('queued','running')
    """),{'c':campaign_id,'now':now,'ev':__import__('json').dumps({'cancellation_reason':reason},ensure_ascii=False)}).rowcount or 0
    db.execute(text("""
      UPDATE attack_campaign_cycles cy
      SET status='cancelled',finished_at=:now,stop_reason='campaign_paused'
      FROM attack_campaign_executions e
      WHERE cy.execution_id=e.id AND e.campaign_id=:c AND cy.status='running'
    """),{'c':campaign_id,'now':now})
    db.execute(text("""
      UPDATE attack_campaign_executions
      SET status='paused',next_cycle_at=NULL
      WHERE campaign_id=:c AND status IN ('scheduled','active')
    """),{'c':campaign_id})
    return {'jobs':int(cancelled_jobs),'paths':int(cancelled_paths)}


def campaign_pause(uuid: str):
    db=db_session()
    try:
        c=db.execute(text('SELECT * FROM attack_campaigns WHERE campaign_uuid=:u FOR UPDATE'),{'u':uuid}).mappings().first()
        if not c: raise ValueError('Campaign não encontrada.')
        db.execute(text("UPDATE attack_campaigns SET status='paused',updated_at=:now WHERE id=:id"),{'now':datetime.utcnow(),'id':c['id']})
        cancelled=_cancel_campaign_jobs(db,int(c['id']),'Campaign pausada pelo usuário')
        db.commit()
        row=get_campaign(uuid)
        return {'success':True,'campaign':row,'cancelled':cancelled}
    except Exception:
        db.rollback(); raise
    finally: db.close()


def campaign_resume(uuid: str):
    db=db_session()
    try:
        c=db.execute(text('SELECT * FROM attack_campaigns WHERE campaign_uuid=:u FOR UPDATE'),{'u':uuid}).mappings().first()
        if not c: raise ValueError('Campaign não encontrada.')
        now=_campaign_now()
        # Resume the latest paused execution without resurrecting cancelled jobs/cycles.
        e=db.execute(text('SELECT * FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1'),{'c':c['id']}).mappings().first()
        if e and e['status']=='paused' and now < e['scheduled_end']:
            db.execute(text("UPDATE attack_campaign_executions SET status='active',next_cycle_at=:now WHERE id=:id"),{'now':now,'id':e['id']})
            status='active'
        else:
            status='scheduled'
        db.execute(text('UPDATE attack_campaigns SET status=:s,updated_at=:now WHERE id=:id'),{'s':status,'now':now,'id':c['id']})
        db.commit()
        return {'success':True,'campaign':get_campaign(uuid)}
    except Exception:
        db.rollback(); raise
    finally: db.close()



def campaign_update(uuid: str, data: dict[str, Any]):
    """Adjust a Campaign while preserving executions, assets and paths."""
    db=db_session()
    try:
        current=db.execute(text('SELECT * FROM attack_campaigns WHERE campaign_uuid=:u FOR UPDATE'),{'u':uuid}).mappings().first()
        if not current: raise ValueError('Campaign não encontrada.')
        merged=dict(current); merged.update(data or {})
        payload=_validate_campaign(merged); now=_campaign_now()
        db.execute(text("""UPDATE attack_campaigns SET name=:name,description=:description,
          scope_cidrs=CAST(:scope AS JSONB),initial_seeds=CAST(:seeds AS JSONB),
          credential_id=:win,ssh_credential_id=:ssh,snmp_credential_id=:snmp,
          enabled_vectors=CAST(:vectors AS JSONB),create_benign_evidence=:evidence,
          start_at=:start,end_at=:end,daily_start=CAST(:ds AS TIME),daily_end=CAST(:de AS TIME),
          cycle_interval_minutes=:interval,cycle_timeout_minutes=:timeout,recurrence_days=:rec,
          max_seeds_per_cycle=3,branch_policy=CAST(:policy AS JSONB),max_paths_per_cycle=:paths,
          max_outstanding_jobs=:jobs,snapshot_retention=:retention,updated_at=:now WHERE id=:id"""),
          {'name':payload['name'],'description':payload.get('description'),'scope':__import__('json').dumps(payload['scope_cidrs']),
           'seeds':__import__('json').dumps(payload['initial_seeds']),'win':payload.get('credential_id'),'ssh':payload.get('ssh_credential_id'),
           'snmp':payload.get('snmp_credential_id'),'vectors':__import__('json').dumps(payload['enabled_vectors']),
           'evidence':bool(payload.get('create_benign_evidence')),'start':payload['start_at'],'end':payload['end_at'],
           'ds':str(payload.get('daily_start') or current['daily_start']),'de':str(payload.get('daily_end') or current['daily_end']),
           'interval':payload['cycle_interval_minutes'],'timeout':payload['cycle_timeout_minutes'],'rec':payload.get('recurrence_days'),
           'policy':__import__('json').dumps(BRANCH_POLICY),'paths':payload['max_paths_per_cycle'],'jobs':payload['max_outstanding_jobs'],
           'retention':payload['snapshot_retention'],'now':now,'id':current['id']})
        db.execute(text("""UPDATE attack_campaign_executions SET scheduled_end=:end WHERE id=(
          SELECT id FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1)
          AND status NOT IN ('completed','cancelled')"""),{'end':payload['end_at'],'c':current['id']})
        db.commit(); return {'success':True,'campaign':get_campaign(uuid),'history_preserved':True}
    except Exception:
        db.rollback(); raise
    finally: db.close()


def campaign_next_cycle_now(uuid: str):
    """Force the current Campaign to close its active cycle and advance."""
    db=db_session()
    try:
        c=db.execute(text('SELECT * FROM attack_campaigns WHERE campaign_uuid=:u FOR UPDATE'),{'u':uuid}).mappings().first()
        if not c: raise ValueError('Campaign não encontrada.')
        e=db.execute(text('SELECT * FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1'),{'c':c['id']}).mappings().first()
        if not e or e['status'] in ('completed','cancelled'): raise ValueError('Campaign sem execução ativa.')
        now=_campaign_now(); cancelled=0
        cy=db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e AND status='running' ORDER BY id DESC LIMIT 1"),{'e':e['id']}).mappings().first()
        if cy:
            ids=[r[0] for r in db.execute(text("SELECT runner_job_id FROM attack_campaign_paths WHERE cycle_id=:cy AND runner_job_id IS NOT NULL AND status IN ('queued','running')"),{'cy':cy['id']}).all()]
            if ids:
                cancelled=db.execute(text("UPDATE runner_jobs SET status='cancelled',error='manual_next_cycle',finished_at=:ts WHERE id=ANY(:ids) AND status IN ('pending','running')"),{'ts':datetime.utcnow(),'ids':ids}).rowcount or 0
            db.execute(text("UPDATE attack_campaign_paths SET status='cancelled',result='manual_next_cycle',finished_at=:ts WHERE cycle_id=:cy AND status IN ('queued','running')"),{'ts':datetime.utcnow(),'cy':cy['id']})
            db.execute(text("UPDATE attack_campaign_cycles SET status='completed',finished_at=:ts,stop_reason='manual_next_cycle' WHERE id=:id"),{'ts':datetime.utcnow(),'id':cy['id']})
        db.execute(text("UPDATE attack_campaign_executions SET status='active',next_cycle_at=:now WHERE id=:id"),{'now':now,'id':e['id']})
        db.execute(text("UPDATE attack_campaigns SET status='active',updated_at=:now WHERE id=:id"),{'now':now,'id':c['id']})
        db.commit(); return {'success':True,'campaign':get_campaign(uuid),'cancelled_jobs':int(cancelled)}
    except Exception:
        db.rollback(); raise
    finally: db.close()


def campaign_delete(uuid: str):
    # Deleting a Campaign must not leave orphaned pending work in the Runner queue.
    db=db_session()
    try:
        c=db.execute(text('SELECT id FROM attack_campaigns WHERE campaign_uuid=:u FOR UPDATE'),{'u':uuid}).mappings().first()
        if not c:
            db.rollback(); return {'success':False}
        cancelled=_cancel_campaign_jobs(db,int(c['id']),'Campaign removida pelo usuário')
        db.execute(text('DELETE FROM attack_campaigns WHERE id=:id'),{'id':c['id']})
        db.commit()
        return {'success':True,'cancelled':cancelled}
    except Exception:
        db.rollback(); raise
    finally: db.close()


def _task_for_protocol(db,protocol:str) -> dict[str,Any] | None:
    key={'winrm':'MAGI-ATK-END-104','smb':'MAGI-ATK-END-102','ssh':'MAGI-ATK-END-103','snmp_v2c':'MAGI-ATK-NET-101'}.get(protocol)
    if not key:return None
    row=db.execute(text('SELECT * FROM validation_tasks WHERE task_key=:k LIMIT 1'),{'k':key}).mappings().first()
    return dict(row) if row else None


def _usable_addresses(scopes: list[str]) -> list[str]:
    out=[]
    for raw in scopes:
        net=ipaddress.ip_network(raw,strict=False)
        for ip in net.hosts(): out.append(str(ip))
    return out


def _inside_daily_window(now: datetime, c: dict[str,Any]) -> bool:
    ds=c['daily_start']; de=c['daily_end']
    if isinstance(ds,str): ds=dtime.fromisoformat(ds)
    if isinstance(de,str): de=dtime.fromisoformat(de)
    t=now.time().replace(tzinfo=None)
    return ds <= t < de


def _window_remaining_minutes(now:datetime,c:dict[str,Any])->float:
    de=c['daily_end'];
    if isinstance(de,str): de=dtime.fromisoformat(de)
    end=datetime.combine(now.date(),de)
    return (end-now).total_seconds()/60


def _upsert_asset(db,eid:int,address:str,*,confirmed=False,hostname=None,inventory=None,increment_seed=False,state=None):
    db.execute(text("""
      INSERT INTO attack_campaign_assets(execution_id,address,hostname,state,access_confirmed,seed_count,inventory,last_seen_at)
      VALUES(:e,:a,:h,:state,:confirmed,:seed,CAST(:inv AS JSONB),:now)
      ON CONFLICT(execution_id,address) DO UPDATE SET
        hostname=COALESCE(EXCLUDED.hostname,attack_campaign_assets.hostname),
        state=CASE WHEN EXCLUDED.access_confirmed THEN 'access_confirmed' ELSE COALESCE(EXCLUDED.state,attack_campaign_assets.state) END,
        access_confirmed=attack_campaign_assets.access_confirmed OR EXCLUDED.access_confirmed,
        seed_count=attack_campaign_assets.seed_count + EXCLUDED.seed_count,
        inventory=COALESCE(attack_campaign_assets.inventory,'{}'::jsonb) || EXCLUDED.inventory,
        last_seen_at=EXCLUDED.last_seen_at
    """),{'e':eid,'a':address,'h':hostname,'state':state or ('access_confirmed' if confirmed else 'discovered'),'confirmed':confirmed,'seed':1 if increment_seed else 0,'inv':__import__('json').dumps(inventory or {},ensure_ascii=False),'now':datetime.utcnow()})


def _select_cycle_seeds(db,c:dict[str,Any],e:dict[str,Any])->list[str]:
    """Select origins for the next Campaign cycle.

    The initial seed remains a valid origin across cycles while it still has
    untested candidates in scope. Build 5.3.10 incorrectly dropped the initial
    seed after cycle 1 and required access_confirmed=TRUE, which caused a
    Campaign with no successful credential hop to finish as scope_exhausted
    after only one cycle.
    """
    cycle_count=db.execute(text('SELECT COUNT(*) FROM attack_campaign_cycles WHERE execution_id=:e'),{'e':e['id']}).scalar() or 0
    if cycle_count==0:
        seeds=list(c.get('initial_seeds') or [])[:3]
        for s in seeds:_upsert_asset(db,e['id'],s,confirmed=False,increment_seed=True,state='seed')
        return seeds

    max_seeds=int(c.get('max_seeds_per_cycle') or 3)
    ordered=[]
    seen=set()

    # Keep operator-provided seeds alive across cycles. They are discovery
    # origins, not one-shot inputs. _candidate_for_origin() is execution-aware,
    # so each new cycle naturally continues with addresses not tested before.
    for address in (c.get('initial_seeds') or []):
        address=str(address)
        if address and address not in seen:
            ordered.append((address,False)); seen.add(address)

    # Successful access paths add new origins for lateral progression.
    rows=db.execute(text("""
      SELECT address FROM attack_campaign_assets
      WHERE execution_id=:e AND access_confirmed=TRUE
      ORDER BY seed_count ASC,last_seen_at DESC,address ASC
    """),{'e':e['id']}).mappings().all()
    for r in rows:
        address=str(r['address'])
        if address and address not in seen:
            ordered.append((address,True)); seen.add(address)

    seeds=[]
    for address,confirmed in ordered:
        if len(seeds)>=max_seeds:
            break
        # Only schedule an origin if there is still at least one distinct path
        # it can evaluate. This makes scope_exhausted a real exhaustion signal.
        if _candidate_for_origin(db,c,e,address) is None:
            continue
        seeds.append(address)
        _upsert_asset(db,e['id'],address,confirmed=confirmed,increment_seed=True,state='access_confirmed' if confirmed else 'seed')
    return seeds


def _candidate_for_origin(db,c:dict[str,Any],e:dict[str,Any],origin:str)->str|None:
    tested={r[0] for r in db.execute(text('SELECT target FROM attack_campaign_paths WHERE execution_id=:e AND origin=:o'),{'e':e['id'],'o':origin}).all()}
    all_tested={r[0] for r in db.execute(text('SELECT target FROM attack_campaign_paths WHERE execution_id=:e'),{'e':e['id']}).all()}
    # Known MAGI assets first, then remaining scope addresses. This still allows unknown hosts to be found progressively.
    known=[]
    try:
        rows=db.execute(text("SELECT host(ip_address) AS ip FROM targets WHERE deleted_at IS NULL ORDER BY last_seen_at DESC LIMIT 2000")).all()
        known=[r[0] for r in rows]
    except Exception: pass
    addresses=_usable_addresses(list(c.get('scope_cidrs') or []))
    allowed=set(addresses)
    ordered=[x for x in known if x in allowed]+addresses
    seen=set()
    for x in ordered:
        if x in seen: continue
        seen.add(x)
        if x==origin or x in tested: continue
        # Stateful: never probe the same target twice in one execution.
        # Confirmed hosts remain reusable as origins/seeds.
        if x not in all_tested: return x
    return None


def _vector_credentials(c:dict[str,Any])->list[tuple[str,int,str]]:
    out=[]; enabled=set(c.get('enabled_vectors') or ['winrm','smb','ssh','snmp_v2c'])
    win=c.get('credential_id'); ssh=c.get('ssh_credential_id'); snmp=c.get('snmp_credential_id')
    if win and 'winrm' in enabled: out.append(('winrm',int(win),'access'))
    if win and 'smb' in enabled: out.append(('smb',int(win),'access'))
    if ssh and 'ssh' in enabled: out.append(('ssh',int(ssh),'access'))
    if snmp and 'snmp_v2c' in enabled: out.append(('snmp_v2c',int(snmp),'discovery'))
    return out


def _runner_id(c:dict[str,Any])->str|None:
    rid=c.get('runner_id')
    if rid:
        return str(rid)
    runner=get_single_online_runner()
    return str((runner or {}).get('runner_id') or '') or None


def _bind_campaign_runner(db, c:dict[str,Any], e:dict[str,Any], now:datetime) -> tuple[str|None,str|None]:
    """Resolve and persist the Runner before a Campaign is allowed to become active.

    Build 5.3.9 removes the previous silent state where a cycle could be shown as
    running while _queue_probe() simply returned False because no usable Runner
    was resolved.
    """
    rid=_runner_id(c)
    if not rid:
        reason='waiting_runner: nenhum Runner online/elegível encontrado'
        db.execute(text("UPDATE attack_campaign_executions SET status='waiting_runner',stats=COALESCE(stats,'{}'::jsonb) || CAST(:st AS JSONB) WHERE id=:id"),
                   {'st':__import__('json').dumps({'scheduler_state':'waiting_runner','scheduler_reason':reason,'scheduler_checked_at':now.isoformat()},ensure_ascii=False),'id':e['id']})
        db.execute(text("UPDATE attack_campaigns SET status='waiting_runner',updated_at=:now WHERE id=:id"),{'now':now,'id':c['id']})
        return None,reason
    if is_runner_queue_paused(rid):
        reason=f'waiting_runner_queue: fila do Runner {rid} está pausada'
        db.execute(text("UPDATE attack_campaign_executions SET status='waiting_runner',stats=COALESCE(stats,'{}'::jsonb) || CAST(:st AS JSONB) WHERE id=:id"),
                   {'st':__import__('json').dumps({'scheduler_state':'waiting_runner_queue','scheduler_reason':reason,'runner_id':rid,'scheduler_checked_at':now.isoformat()},ensure_ascii=False),'id':e['id']})
        db.execute(text("UPDATE attack_campaigns SET status='waiting_runner',runner_id=:r,updated_at=:now WHERE id=:id"),{'r':rid,'now':now,'id':c['id']})
        c['runner_id']=rid
        return None,reason
    if not c.get('runner_id'):
        db.execute(text("UPDATE attack_campaigns SET runner_id=:r,updated_at=:now WHERE id=:id"),{'r':rid,'now':now,'id':c['id']})
        c['runner_id']=rid
    return rid,None


def _queue_probe(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any],origin:str,target:str,depth:int)->bool:
    """Queue one cheap discovery/precondition job for an unknown candidate."""
    runner_id=_runner_id(c)
    if not runner_id:
        raise RuntimeError(f"Campaign {c.get('campaign_uuid')} sem Runner vinculado ao tentar enfileirar preflight")
    exists=db.execute(text("SELECT 1 FROM attack_campaign_paths WHERE execution_id=:e AND origin=:o AND target=:t AND protocol='preflight' LIMIT 1"),{'e':e['id'],'o':origin,'t':target}).first()
    if exists:return False
    enabled=list(c.get('enabled_vectors') or ['winrm','smb','ssh','snmp_v2c'])
    snmp_cred=int(c['snmp_credential_id']) if c.get('snmp_credential_id') and 'snmp_v2c' in enabled else None
    payload={'executor':'campaign_probe','target':target,'enabled_vectors':enabled,'timeout_seconds':6,
             'campaign_context':{'campaign_uuid':c['campaign_uuid'],'execution_id':e['id'],'cycle_id':cy['id'],'origin':origin,'target':target,'depth':depth,'protocol':'preflight'}}
    # Optional SNMP community is injected only in the transient Runner response.
    if snmp_cred:payload['credential_id']=snmp_cred
    job=create_runner_job(runner_id,'campaign_probe',target,payload)
    print(f"[attack-campaign-scheduler] campaign={c['campaign_uuid']} cycle={cy['id']} queued runner_job={job['id']} executor=campaign_probe target={target} runner={runner_id}")
    db.execute(text("""INSERT INTO attack_campaign_paths(execution_id,cycle_id,origin,target,protocol,relation_type,depth,status,runner_job_id)
      VALUES(:e,:cy,:o,:t,'preflight','discovery',:d,'queued',:j) ON CONFLICT(execution_id,origin,target,protocol) DO NOTHING"""),
      {'e':e['id'],'cy':cy['id'],'o':origin,'t':target,'d':depth,'j':job['id']})
    return True


def _queue_access_vectors(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any],origin:str,target:str,depth:int,applicable:list[str])->int:
    """Queue only protocols that passed the Runner-side service precondition."""
    runner_id=_runner_id(c)
    if not runner_id:
        raise RuntimeError(f"Campaign {c.get('campaign_uuid')} sem Runner vinculado ao tentar enfileirar vetor de acesso")
    applicable=set(applicable or [])
    existing={r[0] for r in db.execute(text('SELECT protocol FROM attack_campaign_paths WHERE execution_id=:e AND origin=:o AND target=:t'),{'e':e['id'],'o':origin,'t':target}).all()}
    queued=0
    for protocol,credential_id,relation in _vector_credentials(c):
        # SNMP success is already a real authenticated discovery performed by preflight.
        if protocol=='snmp_v2c':continue
        if protocol not in applicable or protocol in existing:continue
        payload={'executor':'credential_validate','target':target,'credential_id':credential_id,'protocol':protocol,
                 'credential_type':'windows' if protocol in {'winrm','smb'} else 'ssh',
                 'max_attempts':2,'timeout_seconds':30,
                 'create_benign_evidence':bool(c.get('create_benign_evidence')),
                 'evidence_path':r'C:\\MAGI\\MAGI_EVIDENCE.txt',
                 'campaign_context':{'campaign_uuid':c['campaign_uuid'],'execution_id':e['id'],'cycle_id':cy['id'],'origin':origin,'target':target,'depth':depth,'protocol':protocol}}
        job=create_runner_job(runner_id,'credential_validate',target,payload)
        task=_task_for_protocol(db,protocol); vex_id=None
        if task:
            plan={'ready':True,'runner_id':runner_id,'executor':'credential_validate','target':target,'task_id':task['id'],'task_key':task['task_key'],'repository':'magi_attack','credential_id':credential_id,'protocol':protocol,'campaign_uuid':c['campaign_uuid']}
            vex=create_execution(task,runner_id,job['id'],target,f"campaign:{c['campaign_uuid']}",plan); vex_id=vex['id']
        db.execute(text("""INSERT INTO attack_campaign_paths(execution_id,cycle_id,origin,target,protocol,relation_type,depth,status,runner_job_id,validation_execution_id)
          VALUES(:e,:cy,:o,:t,:p,:rel,:d,'queued',:j,:v) ON CONFLICT(execution_id,origin,target,protocol) DO NOTHING"""),
          {'e':e['id'],'cy':cy['id'],'o':origin,'t':target,'p':protocol,'rel':relation,'d':depth,'j':job['id'],'v':vex_id})
        queued+=1
    return queued



def ingest_campaign_runner_result(job_id:int, status:str, data:dict[str,Any]) -> dict[str,Any] | None:
    """Promote a terminal Campaign credential job immediately.

    This path is intentionally independent from the cycle status. A job that
    finishes after its cycle was closed must still update its Campaign path,
    asset and evidence. _sync_paths remains a reconciliation fallback.
    """
    with db_session() as db:
        row=db.execute(text("""
          SELECT p.*,e.id AS execution_pk,c.id AS campaign_pk,c.campaign_uuid,c.runner_id
          FROM attack_campaign_paths p
          JOIN attack_campaign_executions e ON e.id=p.execution_id
          JOIN attack_campaigns c ON c.id=e.campaign_id
          WHERE p.runner_job_id=:j
          LIMIT 1
        """),{'j':int(job_id)}).mappings().first()
        if not row:
            return None

        r=dict(row)
        meta=(data or {}).get('metadata') or {}
        protocol=str(r.get('protocol') or meta.get('protocol') or 'unknown')
        relation=str(r.get('relation_type') or ('discovery' if protocol in {'snmp_v2c','preflight'} else 'access'))
        authenticated=bool(meta.get('authenticated'))
        confirmation=str(meta.get('confirmation_status') or '')

        if authenticated:
            path_status='confirmed'
            result='access_confirmed' if relation=='access' else 'discovery_confirmed'
        elif confirmation in {'runner_dependency_missing','execution_error'} or str(status).lower()=='error':
            path_status='error'
            result=confirmation or 'execution_error'
        else:
            path_status='not_confirmed'
            result=confirmation or ('discovery_not_confirmed' if relation=='discovery' else 'access_not_confirmed')

        evidence=meta or data or {}
        db.execute(text("""
          UPDATE attack_campaign_paths
          SET status=:s,result=:r,evidence=CAST(:ev AS JSONB),finished_at=:now
          WHERE id=:id
        """),{
            's':path_status,'r':result,
            'ev':__import__('json').dumps(evidence,ensure_ascii=False,default=str),
            'now':datetime.utcnow(),'id':r['id']
        })

        if authenticated and relation=='access':
            hostname=meta.get('hostname')
            inv={
                'ip':r['target'],'hostname':hostname,'source':'attack_campaign',
                'protocol':protocol,'relation_type':relation,'last_origin':r['origin'],
                'access_method':protocol,
                'evidence_requested':bool(meta.get('evidence_requested')),
                'evidence_created':bool(meta.get('evidence_created')),
                'evidence_verified':bool(meta.get('evidence_verified')),
                'evidence_path':meta.get('evidence_path'),
            }
            _upsert_asset(
                db,int(r['execution_id']),r['target'],confirmed=True,
                hostname=hostname,inventory=inv,state='access_confirmed'
            )
            try:
                upsert_discovered_target(
                    hostname=hostname,
                    hostname_normalized=(hostname or '').lower() or None,
                    ip_address=r['target'],mac_address=None,mac_normalized=None,
                    status='online',source='attack_campaign',
                    runner_id=r.get('runner_id'),dns_name=None,
                    hostname_source='attack_campaign'
                )
            except Exception:
                pass

        db.commit()
        return {
            'campaign_uuid':r.get('campaign_uuid'),
            'execution_id':r.get('execution_id'),
            'path_id':r.get('id'),
            'path_status':path_status,
            'result':result,
            'authenticated':authenticated,
            'protocol':protocol,
            'target':r.get('target'),
        }

def _sync_paths(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any]):
    rows=db.execute(text("""SELECT p.*,j.status AS job_status,j.result AS job_result,j.error AS job_error
      FROM attack_campaign_paths p JOIN runner_jobs j ON j.id=p.runner_job_id
      WHERE p.cycle_id=:cy AND p.status IN ('queued','running')"""),{'cy':cy['id']}).mappings().all()
    for r in rows:
        js=r['job_status']
        if js in ('pending','running'):
            if js=='running' and r['status']!='running':db.execute(text("UPDATE attack_campaign_paths SET status='running' WHERE id=:id"),{'id':r['id']})
            continue
        data=r['job_result'] or {}; meta=data.get('metadata') or {}
        protocol=str(r.get('protocol') or meta.get('protocol') or 'unknown')
        relation=str(r.get('relation_type') or ('discovery' if protocol in {'snmp_v2c','preflight'} else 'access'))

        if protocol=='preflight':
            alive=bool(meta.get('alive')) and bool(meta.get('icmp')) and str(meta.get('confirmation_status') or '')=='discovery_confirmed'
            result='discovery_confirmed' if alive else 'discovery_not_confirmed'
            status='confirmed' if alive else 'not_confirmed'
            db.execute(text("UPDATE attack_campaign_paths SET status=:s,result=:r,evidence=CAST(:ev AS JSONB),finished_at=:now WHERE id=:id"),
                       {'s':status,'r':result,'ev':__import__('json').dumps(meta or data,ensure_ascii=False,default=str),'now':datetime.utcnow(),'id':r['id']})
            if not alive:
                # Critical 5.3.1 rule: an address that did not answer discovery is NOT an Asset.
                continue
            hostname=meta.get('hostname')
            applicable=list(meta.get('applicable_protocols') or [])
            inv={'ip':r['target'],'hostname':hostname,'source':'attack_campaign','last_origin':r['origin'],'relation_type':'discovery',
                 'open_ports':meta.get('open_ports') or [],'icmp':bool(meta.get('icmp')),'applicable_protocols':applicable,
                 'snmp_confirmed':bool(meta.get('snmp_confirmed'))}
            _upsert_asset(db,e['id'],r['target'],confirmed=False,hostname=hostname,inventory=inv,state='discovered')
            try:upsert_discovered_target(hostname=hostname,hostname_normalized=(hostname or '').lower() or None,ip_address=r['target'],mac_address=None,mac_normalized=None,status='online',source='attack_campaign',runner_id=c.get('runner_id'),dns_name=None,hostname_source='attack_campaign')
            except Exception:pass
            # Preserve SNMP as a concrete discovery relation without repeating the credential test.
            if meta.get('snmp_confirmed'):
                snmp_ev=dict(meta);snmp_ev['protocol']='snmp_v2c';snmp_ev['relation_type']='discovery';snmp_ev['confirmation_status']='discovery_confirmed';snmp_ev['attack_result']='discovery_confirmed'
                db.execute(text("""INSERT INTO attack_campaign_paths(execution_id,cycle_id,origin,target,protocol,relation_type,depth,status,runner_job_id,result,evidence,finished_at)
                  VALUES(:e,:cy,:o,:t,'snmp_v2c','discovery',:d,'confirmed',:j,'discovery_confirmed',CAST(:ev AS JSONB),:now)
                  ON CONFLICT(execution_id,origin,target,protocol) DO NOTHING"""),
                  {'e':e['id'],'cy':cy['id'],'o':r['origin'],'t':r['target'],'d':r['depth'],'j':r['runner_job_id'],'ev':__import__('json').dumps(snmp_ev,ensure_ascii=False,default=str),'now':datetime.utcnow()})
            _queue_access_vectors(db,c,e,cy,r['origin'],r['target'],int(r['depth']),applicable)
            continue

        authenticated=bool(meta.get('authenticated'))
        confirmation=str(meta.get('confirmation_status') or '')
        if authenticated:
            path_status='confirmed'; result='access_confirmed' if relation=='access' else 'discovery_confirmed'
        elif confirmation in {'runner_dependency_missing','execution_error'} or js=='error':
            path_status='error'; result=confirmation or 'execution_error'
        else:
            path_status='not_confirmed'; result=confirmation or ('discovery_not_confirmed' if relation=='discovery' else 'access_not_confirmed')
        db.execute(text("UPDATE attack_campaign_paths SET status=:s,result=:r,evidence=CAST(:ev AS JSONB),finished_at=:now WHERE id=:id"),
                   {'s':path_status,'r':result,'ev':__import__('json').dumps(meta or data,ensure_ascii=False,default=str),'now':datetime.utcnow(),'id':r['id']})
        # Do not create assets here on failures. The target must already have passed preflight.
        if authenticated and relation=='access':
            hostname=meta.get('hostname')
            inv={'ip':r['target'],'hostname':hostname,'source':'attack_campaign','protocol':protocol,'relation_type':relation,'last_origin':r['origin']}
            _upsert_asset(db,e['id'],r['target'],confirmed=True,hostname=hostname,inventory=inv,state='access_confirmed')
            try:upsert_discovered_target(hostname=hostname,hostname_normalized=(hostname or '').lower() or None,ip_address=r['target'],mac_address=None,mac_normalized=None,status='online',source='attack_campaign',runner_id=c.get('runner_id'),dns_name=None,hostname_source='attack_campaign')
            except Exception:pass


def _fill_cycle(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any]):
    _sync_paths(db,c,e,cy)
    total=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy'),{'cy':cy['id']}).scalar() or 0
    outstanding=db.execute(text("SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy AND status IN ('queued','running')"),{'cy':cy['id']}).scalar() or 0
    if total>=int(c.get('max_paths_per_cycle') or 60): return
    slots=max(0,int(c.get('max_outstanding_jobs') or 5)-outstanding)
    if slots<=0:return
    frontier=list(cy.get('frontier') or [])
    # Rebuild frontier from confirmed paths so scheduler restart is harmless.
    for r in db.execute(text("SELECT target,depth FROM attack_campaign_paths WHERE cycle_id=:cy AND status='confirmed' AND relation_type='access' ORDER BY id"),{'cy':cy['id']}).mappings().all():
        next_depth=int(r['depth'])+1
        if next_depth < len(BRANCH_POLICY)-1 and not any(x.get('origin')==r['target'] for x in frontier):
            frontier.append({'origin':r['target'],'depth':next_depth,'limit':BRANCH_POLICY[next_depth],'queued':0})
    for s in (cy.get('seeds') or []):
        if not any(x.get('origin')==s for x in frontier): frontier.insert(0,{'origin':s,'depth':0,'limit':BRANCH_POLICY[0],'queued':0})
    # Round-robin: no initial seed may consume all outstanding slots before the others are evaluated.
    progress=True
    while slots>0 and total<int(c.get('max_paths_per_cycle') or 60) and progress:
        progress=False
        for node in frontier:
            if slots<=0 or total>=int(c.get('max_paths_per_cycle') or 60): break
            origin=node['origin']; depth=int(node.get('depth') or 0); limit=int(BRANCH_POLICY[depth] if depth < len(BRANCH_POLICY) else 0)
            if limit<=0: continue
            count=db.execute(text('SELECT COUNT(DISTINCT target) FROM attack_campaign_paths WHERE cycle_id=:cy AND origin=:o'),{'cy':cy['id'],'o':origin}).scalar() or 0
            if count>=limit: continue
            target=_candidate_for_origin(db,c,e,origin)
            if not target: continue
            if _queue_probe(db,c,e,cy,origin,target,depth):
                total+=1; slots-=1; progress=True
    db.execute(text('UPDATE attack_campaign_cycles SET frontier=CAST(:f AS JSONB),stats=CAST(:s AS JSONB) WHERE id=:id'),
               {'f':__import__('json').dumps(frontier,ensure_ascii=False),'s':__import__('json').dumps({'paths':total,'outstanding':outstanding},ensure_ascii=False),'id':cy['id']})


def _finalize_cycle(db,c,e,cy,reason):
    # Cancel only pending jobs created by this cycle. Running job is allowed to finish and will be ingested later.
    db.execute(text("""UPDATE runner_jobs SET status='cancelled',error='Campaign cycle timeout' WHERE id IN
      (SELECT runner_job_id FROM attack_campaign_paths WHERE cycle_id=:cy AND status='queued') AND status='pending'"""),{'cy':cy['id']})
    db.execute(text("UPDATE attack_campaign_paths SET status='cycle_timeout',result='cycle_timeout',finished_at=:now WHERE cycle_id=:cy AND status='queued'"),{'cy':cy['id'],'now':datetime.utcnow()})
    stats=dict(db.execute(text("""SELECT COUNT(*) AS paths,COUNT(*) FILTER(WHERE status='confirmed') AS confirmed,
      COUNT(*) FILTER(WHERE status='not_confirmed') AS not_confirmed FROM attack_campaign_paths WHERE cycle_id=:cy"""),{'cy':cy['id']}).mappings().first())
    db.execute(text("UPDATE attack_campaign_cycles SET status='completed',finished_at=:now,stop_reason=:r,stats=CAST(:s AS JSONB) WHERE id=:id"),
               {'now':datetime.utcnow(),'r':reason,'s':__import__('json').dumps(stats,default=int),'id':cy['id']})
    # A cycle may last up to 15 minutes; completion does not impose idle time.
    now_local=_campaign_now(); nxt=now_local
    db.execute(text("UPDATE attack_campaign_executions SET next_cycle_at=:n,stats=CAST(:s AS JSONB) WHERE id=:e"),{'n':nxt,'s':__import__('json').dumps(_execution_stats(db,e['id']),default=int),'e':e['id']})


def _execution_stats(db,eid:int)->dict[str,int]:
    a=dict(db.execute(text("SELECT COUNT(*) AS discovered,COUNT(*) FILTER(WHERE access_confirmed) AS accessed FROM attack_campaign_assets WHERE execution_id=:e"),{'e':eid}).mappings().first())
    p=dict(db.execute(text("SELECT COUNT(*) AS paths,COUNT(*) FILTER(WHERE status='confirmed') AS confirmed FROM attack_campaign_paths WHERE execution_id=:e"),{'e':eid}).mappings().first())
    return {**{k:int(v or 0) for k,v in a.items()},**{k:int(v or 0) for k,v in p.items()}}


def _snapshot(db,eid:int)->dict[str,Any]:
    assets=[dict(x) for x in db.execute(text('SELECT address,hostname,state,access_confirmed,inventory,first_seen_at,last_seen_at FROM attack_campaign_assets WHERE execution_id=:e ORDER BY address'),{'e':eid}).mappings().all()]
    paths=[dict(x) for x in db.execute(text("SELECT origin,target,protocol,relation_type,depth,status,result,evidence,created_at,finished_at FROM attack_campaign_paths WHERE execution_id=:e ORDER BY id"),{'e':eid}).mappings().all()]
    return {'stats':_execution_stats(db,eid),'assets':assets,'paths':paths,'generated_at':datetime.utcnow().isoformat()}


def _finish_execution(db,c,e,reason):
    snap=_snapshot(db,e['id'])
    db.execute(text("UPDATE attack_campaign_executions SET status='completed',finished_at=:now,stop_reason=:r,stats=CAST(:st AS JSONB),final_snapshot=CAST(:snap AS JSONB) WHERE id=:e"),
               {'now':datetime.utcnow(),'r':reason,'st':__import__('json').dumps(snap['stats']),'snap':__import__('json').dumps(snap,ensure_ascii=False,default=str),'e':e['id']})
    # Compact retention: only final snapshots of the newest N executions survive.
    retention=int(c.get('snapshot_retention') or 10)
    old=db.execute(text('SELECT id FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC OFFSET :n'),{'c':c['id'],'n':retention}).all()
    for (oid,) in old: db.execute(text('DELETE FROM attack_campaign_executions WHERE id=:id'),{'id':oid})
    rec=c.get('recurrence_days')
    if rec:
        duration=e['scheduled_end']-e['scheduled_start']; new_start=e['scheduled_end']+timedelta(days=int(rec)); new_end=new_start+duration
        num=int(e['execution_number'])+1
        db.execute(text("INSERT INTO attack_campaign_executions(campaign_id,execution_number,status,scheduled_start,scheduled_end,next_cycle_at) VALUES(:c,:n,'scheduled',:s,:e,:s) ON CONFLICT DO NOTHING"),{'c':c['id'],'n':num,'s':new_start,'e':new_end})
        db.execute(text("UPDATE attack_campaigns SET status='scheduled',updated_at=:now WHERE id=:id"),{'now':datetime.utcnow(),'id':c['id']})
    else: db.execute(text("UPDATE attack_campaigns SET status='completed',updated_at=:now WHERE id=:id"),{'now':datetime.utcnow(),'id':c['id']})


def process_campaigns_once(now:datetime|None=None):
    now=now or _campaign_now()
    db=db_session()
    try:
        campaigns=[dict(x) for x in db.execute(text("SELECT * FROM attack_campaigns WHERE enabled=TRUE AND status NOT IN ('completed','cancelled','paused','blocked') ORDER BY id")).mappings().all()]
        for c in campaigns:
            e0=db.execute(text("SELECT * FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1"),{'c':c['id']}).mappings().first()
            if not e0: continue
            e=dict(e0)
            if now < e['scheduled_start']: continue
            if now >= e['scheduled_end']:
                active=db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e AND status='running' ORDER BY id DESC LIMIT 1"),{'e':e['id']}).mappings().first()
                if active:_finalize_cycle(db,c,e,dict(active),'execution_window_ended')
                _finish_execution(db,c,e,'time_window_reached'); continue
            # A Campaign only becomes active after a concrete, unpaused Runner is bound.
            # This guarantees that 'active' means the backend is actually able to create work.
            rid,wait_reason=_bind_campaign_runner(db,c,e,now)
            if not rid:
                continue
            if e['status'] in ('scheduled','waiting_runner'):
                db.execute(text("UPDATE attack_campaign_executions SET status='active',started_at=COALESCE(started_at,:now),next_cycle_at=CASE WHEN next_cycle_at IS NULL OR next_cycle_at>:now THEN :now ELSE next_cycle_at END,stats=COALESCE(stats,'{}'::jsonb) || CAST(:st AS JSONB) WHERE id=:id"),
                           {'now':now,'id':e['id'],'st':__import__('json').dumps({'scheduler_state':'runner_bound','runner_id':rid,'scheduler_checked_at':now.isoformat()},ensure_ascii=False)}); e['status']='active'; e['next_cycle_at']=now
                db.execute(text("UPDATE attack_campaigns SET status='active',runner_id=:r,updated_at=:now WHERE id=:id"),{'r':rid,'now':now,'id':c['id']})
            active=db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e AND status='running' ORDER BY id DESC LIMIT 1"),{'e':e['id']}).mappings().first()
            if active:
                cy=dict(active); _fill_cycle(db,c,e,cy)
                if now >= cy['deadline_at']:
                    _sync_paths(db,c,e,cy); _finalize_cycle(db,c,e,cy,'cycle_timeout')
                    continue
                outstanding=db.execute(text("SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy AND status IN ('queued','running')"),{'cy':cy['id']}).scalar() or 0
                before=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy'),{'cy':cy['id']}).scalar() or 0
                if int(outstanding)==0:
                    _fill_cycle(db,c,e,cy)
                    after=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy'),{'cy':cy['id']}).scalar() or 0
                    outstanding2=db.execute(text("SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy AND status IN ('queued','running')"),{'cy':cy['id']}).scalar() or 0
                    if int(outstanding2)==0 and int(after)==int(before):
                        _finalize_cycle(db,c,e,cy,'cycle_completed')
                continue
            if not _inside_daily_window(now,c): continue
            if _window_remaining_minutes(now,c) < int(c.get('cycle_timeout_minutes') or 15): continue
            if e.get('next_cycle_at') and now < e['next_cycle_at']: continue
            number=(db.execute(text('SELECT COALESCE(MAX(cycle_number),0)+1 FROM attack_campaign_cycles WHERE execution_id=:e'),{'e':e['id']}).scalar() or 1)
            seeds=_select_cycle_seeds(db,c,e)
            if not seeds:
                _finish_execution(db,c,e,'scope_exhausted'); continue
            deadline=now+timedelta(minutes=int(c.get('cycle_timeout_minutes') or 15))
            cyrow=db.execute(text("INSERT INTO attack_campaign_cycles(execution_id,cycle_number,status,scheduled_at,started_at,deadline_at,seeds,frontier) VALUES(:e,:n,'running',:now,:now,:d,CAST(:s AS JSONB),'[]'::jsonb) RETURNING *"),
                             {'e':e['id'],'n':number,'now':now,'d':deadline,'s':__import__('json').dumps(seeds)}).mappings().first()
            cy=dict(cyrow)
            _fill_cycle(db,c,e,cy)
            path_count=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy'),{'cy':cy['id']}).scalar() or 0
            if int(path_count)==0:
                reason='no_jobs_queued: ciclo criado mas nenhum path/job foi gerado'
                db.execute(text("UPDATE attack_campaign_cycles SET status='blocked',stop_reason=:r,finished_at=:now,stats=COALESCE(stats,'{}'::jsonb) || CAST(:st AS JSONB) WHERE id=:id"),
                           {'r':reason,'now':now,'id':cy['id'],'st':__import__('json').dumps({'scheduler_state':'blocked','scheduler_reason':reason,'runner_id':rid},ensure_ascii=False)})
                db.execute(text("UPDATE attack_campaign_executions SET status='blocked',stats=COALESCE(stats,'{}'::jsonb) || CAST(:st AS JSONB) WHERE id=:id"),
                           {'id':e['id'],'st':__import__('json').dumps({'scheduler_state':'blocked','scheduler_reason':reason,'runner_id':rid,'scheduler_checked_at':now.isoformat()},ensure_ascii=False)})
                db.execute(text("UPDATE attack_campaigns SET status='blocked',updated_at=:now WHERE id=:id"),{'now':now,'id':c['id']})
                print(f"[attack-campaign-scheduler] campaign={c['campaign_uuid']} BLOCKED reason={reason} runner={rid}")
        db.commit()
    except Exception:
        db.rollback(); raise
    finally: db.close()
