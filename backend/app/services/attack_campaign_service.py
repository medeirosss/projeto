from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, time as dtime
from typing import Any
from sqlalchemy import text

from app.repositories.attack_campaign_repository import create_campaign, list_campaigns, get_campaign, set_campaign_status, delete_campaign, db_session
from app.repositories.runner_repository import create_runner_job, get_single_online_runner
from app.repositories.validation_repository import list_tasks, create_execution
from app.repositories.target_repository import upsert_discovered_target

BRANCH_POLICY = [10, 5, 1, 0]


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
    return {**data,'name':name,'initial_seeds':seeds,'scope_cidrs':scopes,'start_at':start,'end_at':end,
            'cycle_interval_minutes':interval,'cycle_timeout_minutes':timeout,'recurrence_days':int(recurrence) if recurrence else None,
            'max_seeds_per_cycle':3,'branch_policy':BRANCH_POLICY,'max_paths_per_cycle':max(10,min(100,int(data.get('max_paths_per_cycle') or 60))),
            'max_outstanding_jobs':max(1,min(10,int(data.get('max_outstanding_jobs') or 5))),'snapshot_retention':10}


def create_attack_campaign(data: dict[str, Any], requested_by: str) -> dict[str, Any]:
    payload=_validate_campaign(data)
    row=create_campaign(payload, requested_by)
    return {'success':True,'campaign':row,'policy':{'branch_policy':BRANCH_POLICY,'snapshot_retention':10,'cycle_timeout_max_minutes':15}}


def campaign_list() -> dict[str, Any]: return {'success':True,'campaigns':list_campaigns()}
def campaign_detail(uuid: str) -> dict[str, Any]:
    row=get_campaign(uuid)
    if not row: raise ValueError('Campaign não encontrada.')
    return {'success':True,'campaign':row}
def campaign_pause(uuid: str):
    row=set_campaign_status(uuid,'paused')
    if not row: raise ValueError('Campaign não encontrada.')
    return {'success':True,'campaign':row}
def campaign_resume(uuid: str):
    row=set_campaign_status(uuid,'scheduled')
    if not row: raise ValueError('Campaign não encontrada.')
    return {'success':True,'campaign':row}
def campaign_delete(uuid: str): return {'success':delete_campaign(uuid)}


def _task_end101(db) -> dict[str,Any] | None:
    row=db.execute(text("SELECT * FROM validation_tasks WHERE task_key='MAGI-ATK-END-101' LIMIT 1")).mappings().first()
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
    cycle_count=db.execute(text('SELECT COUNT(*) FROM attack_campaign_cycles WHERE execution_id=:e'),{'e':e['id']}).scalar() or 0
    if cycle_count==0:
        seeds=list(c.get('initial_seeds') or [])[:3]
        for s in seeds:_upsert_asset(db,e['id'],s,confirmed=False,increment_seed=True,state='seed')
        return seeds
    rows=db.execute(text("""
      SELECT address FROM attack_campaign_assets
      WHERE execution_id=:e AND access_confirmed=TRUE
      ORDER BY seed_count ASC,last_seen_at DESC,address ASC LIMIT :n
    """),{'e':e['id'],'n':int(c.get('max_seeds_per_cycle') or 3)}).mappings().all()
    seeds=[r['address'] for r in rows]
    for s in seeds:_upsert_asset(db,e['id'],s,confirmed=True,increment_seed=True)
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
        # Prefer never-evaluated hosts, but permit a different origin to validate a distinct path later.
        if x not in all_tested: return x
    for x in ordered:
        if x!=origin and x not in tested: return x
    return None


def _queue_path(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any],origin:str,target:str,depth:int)->bool:
    task=_task_end101(db)
    if not task:return False
    runner_id=c.get('runner_id')
    if not runner_id:
        runner=get_single_online_runner(); runner_id=(runner or {}).get('runner_id')
    if not runner_id:return False
    scope={'mode':'campaign_5_2','max_hops':3,'hard_max_hops':5,'allowed_hosts':[origin,target],
           'allowed_networks':list(c.get('scope_cidrs') or []),'initial_target':origin,'secondary_target':target,
           'discovery_enabled':True,'branch_policy':BRANCH_POLICY,'campaign_uuid':c['campaign_uuid'],'cycle_id':cy['id']}
    payload={'executor':'attack_simulation','validation_type':'attack_simulation','task_id':task['id'],'task_key':task['task_key'],
             'repository_key':'magi_attack','target':origin,'detection':task.get('detection') or {},'impact':task.get('impact'),
             'remediation':task.get('remediation'),'simulation':task.get('detection') or {},'scenario_name':task.get('name'),
             'attack_category':task.get('category'),'attack_metadata':task.get('metadata') or {},'safe_mode':True,'destructive':False,
             'scope':scope,'credential_id':c.get('credential_id'),'host_b':target,'campaign_context':{'campaign_uuid':c['campaign_uuid'],'execution_id':e['id'],'cycle_id':cy['id'],'depth':depth},
             'timeout_seconds':min(180,int(c.get('cycle_timeout_minutes') or 15)*60)}
    job=create_runner_job(runner_id,'attack_simulation',origin,payload)
    plan={'ready':True,'runner_id':runner_id,'executor':'attack_simulation','target':origin,'task_id':task['id'],'task_key':task['task_key'],'repository':'magi_attack','scope':scope,'credential_id':c.get('credential_id')}
    vex=create_execution(task,runner_id,job['id'],origin,f"campaign:{c['campaign_uuid']}",plan)
    db.execute(text("""INSERT INTO attack_campaign_paths(execution_id,cycle_id,origin,target,depth,status,runner_job_id,validation_execution_id)
      VALUES(:e,:cy,:o,:t,:d,'queued',:j,:v) ON CONFLICT(execution_id,origin,target) DO NOTHING"""),
      {'e':e['id'],'cy':cy['id'],'o':origin,'t':target,'d':depth,'j':job['id'],'v':vex['id']})
    return True


def _sync_paths(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any]):
    rows=db.execute(text("""SELECT p.*,j.status AS job_status,j.result AS job_result,j.error AS job_error
      FROM attack_campaign_paths p JOIN runner_jobs j ON j.id=p.runner_job_id
      WHERE p.cycle_id=:cy AND p.status IN ('queued','running')"""),{'cy':cy['id']}).mappings().all()
    for r in rows:
        js=r['job_status']
        if js in ('pending','running'):
            if js=='running' and r['status']!='running': db.execute(text("UPDATE attack_campaign_paths SET status='running' WHERE id=:id"),{'id':r['id']})
            continue
        data=r['job_result'] or {}; meta=data.get('metadata') or {}; ev=meta.get('evidence') or {}
        attack=meta.get('attack_result') or ev.get('attack_result') or 'not_confirmed'
        confirmed=attack=='lateral_movement_confirmed'
        db.execute(text("UPDATE attack_campaign_paths SET status=:s,result=:r,evidence=CAST(:ev AS JSONB),finished_at=:now WHERE id=:id"),
                   {'s':'confirmed' if confirmed else 'not_confirmed','r':attack,'ev':__import__('json').dumps(ev or data,ensure_ascii=False,default=str),'now':datetime.utcnow(),'id':r['id']})
        _upsert_asset(db,e['id'],r['target'],confirmed=confirmed,state='access_confirmed' if confirmed else 'evaluated')
        if confirmed:
            remote=ev.get('remote_evidence') or {}; ha=remote.get('host_a') or {}; hb=remote.get('host_b') or {}; hostname=hb.get('hostname')
            _upsert_asset(db,e['id'],r['origin'],confirmed=True,hostname=ha.get('hostname'),inventory={'ip':r['origin'],'hostname':ha.get('hostname'),'source':'attack_campaign','access_protocol':'winrm'})
            inventory={'ip':r['target'],'hostname':hostname,'source':'attack_campaign','access_protocol':'winrm','last_path':f"{r['origin']} -> {r['target']}"}
            _upsert_asset(db,e['id'],r['target'],confirmed=True,hostname=hostname,inventory=inventory)
            try: upsert_discovered_target(hostname=hostname,hostname_normalized=(hostname or '').lower() or None,ip_address=r['target'],mac_address=None,mac_normalized=None,status='online',source='attack_campaign',runner_id=c.get('runner_id'),dns_name=None,hostname_source='attack_campaign')
            except Exception: pass


def _fill_cycle(db,c:dict[str,Any],e:dict[str,Any],cy:dict[str,Any]):
    _sync_paths(db,c,e,cy)
    total=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy'),{'cy':cy['id']}).scalar() or 0
    outstanding=db.execute(text("SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy AND status IN ('queued','running')"),{'cy':cy['id']}).scalar() or 0
    if total>=int(c.get('max_paths_per_cycle') or 60): return
    slots=max(0,int(c.get('max_outstanding_jobs') or 5)-outstanding)
    if slots<=0:return
    frontier=list(cy.get('frontier') or [])
    # Rebuild frontier from confirmed paths so scheduler restart is harmless.
    for r in db.execute(text("SELECT target,depth FROM attack_campaign_paths WHERE cycle_id=:cy AND status='confirmed' ORDER BY id"),{'cy':cy['id']}).mappings().all():
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
            count=db.execute(text('SELECT COUNT(*) FROM attack_campaign_paths WHERE cycle_id=:cy AND origin=:o'),{'cy':cy['id'],'o':origin}).scalar() or 0
            if count>=limit: continue
            target=_candidate_for_origin(db,c,e,origin)
            if not target: continue
            if _queue_path(db,c,e,cy,origin,target,depth):
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
    base=cy.get('started_at') or datetime.utcnow(); planned=base+timedelta(minutes=int(c.get('cycle_interval_minutes') or 15)); nxt=max(datetime.utcnow(),planned)
    db.execute(text("UPDATE attack_campaign_executions SET next_cycle_at=:n,stats=CAST(:s AS JSONB) WHERE id=:e"),{'n':nxt,'s':__import__('json').dumps(_execution_stats(db,e['id']),default=int),'e':e['id']})


def _execution_stats(db,eid:int)->dict[str,int]:
    a=dict(db.execute(text("SELECT COUNT(*) AS discovered,COUNT(*) FILTER(WHERE access_confirmed) AS accessed FROM attack_campaign_assets WHERE execution_id=:e"),{'e':eid}).mappings().first())
    p=dict(db.execute(text("SELECT COUNT(*) AS paths,COUNT(*) FILTER(WHERE status='confirmed') AS confirmed FROM attack_campaign_paths WHERE execution_id=:e"),{'e':eid}).mappings().first())
    return {**{k:int(v or 0) for k,v in a.items()},**{k:int(v or 0) for k,v in p.items()}}


def _snapshot(db,eid:int)->dict[str,Any]:
    assets=[dict(x) for x in db.execute(text('SELECT address,hostname,state,access_confirmed,inventory,first_seen_at,last_seen_at FROM attack_campaign_assets WHERE execution_id=:e ORDER BY address'),{'e':eid}).mappings().all()]
    paths=[dict(x) for x in db.execute(text("SELECT origin,target,depth,status,result,evidence,created_at,finished_at FROM attack_campaign_paths WHERE execution_id=:e ORDER BY id"),{'e':eid}).mappings().all()]
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
    now=now or datetime.utcnow()
    db=db_session()
    try:
        campaigns=[dict(x) for x in db.execute(text("SELECT * FROM attack_campaigns WHERE enabled=TRUE AND status NOT IN ('completed','cancelled','paused') ORDER BY id")).mappings().all()]
        for c in campaigns:
            e0=db.execute(text("SELECT * FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1"),{'c':c['id']}).mappings().first()
            if not e0: continue
            e=dict(e0)
            if now < e['scheduled_start']: continue
            if now >= e['scheduled_end']:
                active=db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e AND status='running' ORDER BY id DESC LIMIT 1"),{'e':e['id']}).mappings().first()
                if active:_finalize_cycle(db,c,e,dict(active),'execution_window_ended')
                _finish_execution(db,c,e,'time_window_reached'); continue
            if e['status']=='scheduled':
                db.execute(text("UPDATE attack_campaign_executions SET status='active',started_at=COALESCE(started_at,:now),next_cycle_at=GREATEST(next_cycle_at,:now) WHERE id=:id"),{'now':now,'id':e['id']}); e['status']='active'
                db.execute(text("UPDATE attack_campaigns SET status='active',updated_at=:now WHERE id=:id"),{'now':now,'id':c['id']})
            active=db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e AND status='running' ORDER BY id DESC LIMIT 1"),{'e':e['id']}).mappings().first()
            if active:
                cy=dict(active); _fill_cycle(db,c,e,cy)
                if now >= cy['deadline_at']:
                    _sync_paths(db,c,e,cy); _finalize_cycle(db,c,e,cy,'cycle_timeout')
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
            _fill_cycle(db,c,e,dict(cyrow))
        db.commit()
    except Exception:
        db.rollback(); raise
    finally: db.close()
