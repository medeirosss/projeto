"""MAGI 5.9: conservative, unauthenticated, Runner-backed baseline monitoring.

Only hosts already observed in the latest Campaign baseline are probed. A failed
scan is INCONCLUSIVE, never evidence of an unavailable host. No credential jobs.
"""
from __future__ import annotations
import ipaddress
import json
from datetime import datetime, timedelta
from sqlalchemy import text
from app.database.connection import SessionLocal
from app.repositories.runner_repository import create_runner_job, get_online_runner_with_capability

INTERVAL_MINUTES = 60
CONFIRMATIONS = 2


def ensure_monitoring_schema():
    with SessionLocal() as db:
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_policies (
            id BIGSERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL UNIQUE REFERENCES attack_campaigns(id) ON DELETE CASCADE,
            enabled BOOLEAN NOT NULL DEFAULT FALSE, interval_minutes INTEGER NOT NULL DEFAULT 60,
            mode VARCHAR(20) NOT NULL DEFAULT 'light', authenticated BOOLEAN NOT NULL DEFAULT FALSE,
            confirmations INTEGER NOT NULL DEFAULT 2, next_run_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_runs (
            id BIGSERIAL PRIMARY KEY, policy_id BIGINT NOT NULL REFERENCES security_monitor_policies(id) ON DELETE CASCADE,
            baseline_id BIGINT NOT NULL REFERENCES attack_campaign_baselines(id) ON DELETE CASCADE,
            status VARCHAR(24) NOT NULL DEFAULT 'running', started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP, summary JSONB NOT NULL DEFAULT '{}'::jsonb)'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_checks (
            id BIGSERIAL PRIMARY KEY, run_id BIGINT NOT NULL REFERENCES security_monitor_runs(id) ON DELETE CASCADE,
            ip_address VARCHAR(45) NOT NULL, runner_job_id BIGINT UNIQUE REFERENCES runner_jobs(id) ON DELETE SET NULL,
            status VARCHAR(24) NOT NULL DEFAULT 'queued', result JSONB,
            UNIQUE(run_id,ip_address))'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_events (
            id BIGSERIAL PRIMARY KEY, policy_id BIGINT NOT NULL REFERENCES security_monitor_policies(id) ON DELETE CASCADE,
            run_id BIGINT NOT NULL REFERENCES security_monitor_runs(id) ON DELETE CASCADE,
            ip_address VARCHAR(45) NOT NULL, event_type VARCHAR(40) NOT NULL,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(policy_id,run_id,ip_address,event_type))'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_service_checks (
            id BIGSERIAL PRIMARY KEY, run_id BIGINT NOT NULL REFERENCES security_monitor_runs(id) ON DELETE CASCADE,
            ip_address VARCHAR(45) NOT NULL, port INTEGER NOT NULL, protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
            runner_job_id BIGINT REFERENCES runner_jobs(id) ON DELETE SET NULL,
            status VARCHAR(24) NOT NULL DEFAULT 'queued', observed_state VARCHAR(24),
            result JSONB, UNIQUE(run_id,ip_address,port,protocol))'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_monitor_alerts (
            id BIGSERIAL PRIMARY KEY,
            event_id BIGINT NOT NULL UNIQUE REFERENCES security_monitor_events(id) ON DELETE CASCADE,
            policy_id BIGINT NOT NULL REFERENCES security_monitor_policies(id) ON DELETE CASCADE,
            status VARCHAR(20) NOT NULL DEFAULT 'open',
            severity VARCHAR(16) NOT NULL DEFAULT 'warning',
            acknowledged_at TIMESTAMP, closed_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT security_monitor_alert_status CHECK(status IN ('open','acknowledged','closed'))
        )'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_service_alert_policies (
            id BIGSERIAL PRIMARY KEY, target_uuid VARCHAR(128) NOT NULL,
            ip_address VARCHAR(45) NOT NULL, protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
            port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
            enabled BOOLEAN NOT NULL DEFAULT TRUE, condition VARCHAR(20) NOT NULL DEFAULT 'unavailable',
            polls INTEGER NOT NULL DEFAULT 2 CHECK(polls BETWEEN 1 AND 20),
            cooldown_minutes INTEGER NOT NULL DEFAULT 60 CHECK(cooldown_minutes BETWEEN 0 AND 10080),
            severity VARCHAR(16) NOT NULL DEFAULT 'warning',
            last_state VARCHAR(24), consecutive INTEGER NOT NULL DEFAULT 0,
            last_run_id BIGINT, last_notified_at TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(target_uuid,protocol,port))'''))
        db.execute(text('''CREATE TABLE IF NOT EXISTS security_service_alerts (
            id BIGSERIAL PRIMARY KEY, service_policy_id BIGINT NOT NULL REFERENCES security_service_alert_policies(id) ON DELETE CASCADE,
            monitor_run_id BIGINT REFERENCES security_monitor_runs(id) ON DELETE SET NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'open', severity VARCHAR(16) NOT NULL,
            event_type VARCHAR(40) NOT NULL DEFAULT 'SERVICE_UNAVAILABLE',
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_notified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            notification_count INTEGER NOT NULL DEFAULT 1,
            resolved_at TIMESTAMP, acknowledged_at TIMESTAMP,
            CONSTRAINT service_alert_status CHECK(status IN ('open','acknowledged','closed'))'''))
        db.execute(text('''CREATE UNIQUE INDEX IF NOT EXISTS service_alert_one_active
            ON security_service_alerts(service_policy_id) WHERE status IN ('open','acknowledged')'''))
        db.commit()


def _campaign(db, campaign_uuid):
    row=db.execute(text('SELECT id,campaign_uuid FROM attack_campaigns WHERE campaign_uuid=:u'),{'u':campaign_uuid}).mappings().first()
    if not row: raise ValueError('Campaign não encontrada')
    return dict(row)


def configure(campaign_uuid, enabled):
    with SessionLocal() as db:
        campaign=_campaign(db,campaign_uuid)
        baseline=db.execute(text('SELECT id FROM attack_campaign_baselines WHERE campaign_id=:c ORDER BY id DESC LIMIT 1'),{'c':campaign['id']}).first()
        if enabled and not baseline: raise ValueError('Finalize uma execução do Campaign antes de habilitar o monitoramento')
        db.execute(text('''INSERT INTO security_monitor_policies(campaign_id,enabled,next_run_at)
            VALUES(:c,:e,CASE WHEN :e THEN CURRENT_TIMESTAMP ELSE NULL END)
            ON CONFLICT(campaign_id) DO UPDATE SET enabled=:e,
            next_run_at=CASE WHEN :e THEN CURRENT_TIMESTAMP ELSE NULL END,updated_at=CURRENT_TIMESTAMP'''),{'c':campaign['id'],'e':enabled})
        db.commit()
    return {'success':True,'campaign_uuid':campaign_uuid,'enabled':enabled,'interval_minutes':60,'mode':'light','authenticated':False,'confirmations':2}


def verify_now(campaign_uuid):
    with SessionLocal() as db:
        campaign=_campaign(db,campaign_uuid)
        policy=db.execute(text('SELECT id,enabled FROM security_monitor_policies WHERE campaign_id=:c FOR UPDATE'),{'c':campaign['id']}).mappings().first()
        if not policy or not policy['enabled']: raise ValueError('Habilite o Monitoring antes de verificar agora')
        active=db.execute(text("SELECT id FROM security_monitor_runs WHERE policy_id=:p AND status='running' LIMIT 1"),{'p':policy['id']}).scalar()
        if active: raise ValueError('Já existe uma verificação em andamento')
        db.execute(text('UPDATE security_monitor_policies SET next_run_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=:p'),{'p':policy['id']})
        db.commit()
    tick()
    return {'success':True,'message':'Verificação solicitada','campaign_uuid':campaign_uuid}


def _known_ports(snapshot):
    out={}
    for asset in snapshot.get('assets',[]):
        ip=asset.get('address')
        try:
            if not ipaddress.ip_address(ip).is_private: continue
        except (ValueError,TypeError): continue
        inv=asset.get('inventory') or {}
        if not isinstance(inv,dict): continue
        ports=inv.get('open_ports') or inv.get('ports') or []
        if not isinstance(ports,list): continue
        for item in ports:
            try:
                port=int(item.get('port') or item.get('portid')) if isinstance(item,dict) else int(item)
                proto=str(item.get('protocol','tcp')).lower() if isinstance(item,dict) else 'tcp'
                if 1<=port<=65535 and proto=='tcp':out.setdefault(ip,set()).add(port)
            except (TypeError,ValueError): pass
    return {ip:sorted(ports)[:64] for ip,ports in out.items()}


def _job_payload(result):
    if isinstance(result,str):
        try: result=json.loads(result)
        except (TypeError,ValueError):return {}
    if not isinstance(result,dict):return {}
    for key in ('metadata','result'):
        if isinstance(result.get(key),dict):return _job_payload(result[key])
    return result


def _service_states(result):
    data=_job_payload(result)
    states=data.get('port_states')
    if not isinstance(states,list):return {}
    out={}
    for item in states:
        if not isinstance(item,dict):continue
        try:
            port=int(item.get('port'))
            state=str(item.get('state','')).lower()
            if state in ('open','closed') and 1<=port<=65535:out[port]=state
        except (TypeError,ValueError):pass
    return out


def status(campaign_uuid):
    with SessionLocal() as db:
        campaign=_campaign(db,campaign_uuid)
        policy=db.execute(text('SELECT * FROM security_monitor_policies WHERE campaign_id=:c'),{'c':campaign['id']}).mappings().first()
        if not policy:return {'success':True,'enabled':False,'interval_minutes':60,'mode':'light','authenticated':False,'confirmations':2,'runs':[],'events':[],'alerts':[]}
        runs=db.execute(text('SELECT id,baseline_id,status,started_at,finished_at,summary FROM security_monitor_runs WHERE policy_id=:p ORDER BY id DESC LIMIT 20'),{'p':policy['id']}).mappings().all()
        events=db.execute(text('SELECT id,run_id,ip_address,event_type,details,created_at FROM security_monitor_events WHERE policy_id=:p ORDER BY id DESC LIMIT 100'),{'p':policy['id']}).mappings().all()
        alerts=db.execute(text('''SELECT a.id,a.event_id,a.status,a.severity,a.created_at,a.acknowledged_at,a.closed_at,
            e.ip_address,e.event_type,e.details FROM security_monitor_alerts a
            JOIN security_monitor_events e ON e.id=a.event_id WHERE a.policy_id=:p
            ORDER BY a.id DESC LIMIT 100'''),{'p':policy['id']}).mappings().all()
        return {'success':True,'enabled':policy['enabled'],'interval_minutes':policy['interval_minutes'],'mode':policy['mode'],'authenticated':policy['authenticated'],'confirmations':policy['confirmations'],'next_run_at':policy['next_run_at'],'runs':[dict(r) for r in runs],'events':[dict(r) for r in events],'alerts':[dict(a) for a in alerts]}


def _ips(snapshot):
    seen=set()
    for asset in snapshot.get('assets',[]):
        address=asset.get('address')
        try:
            ip=ipaddress.ip_address(address)
            if ip.is_private and not ip.is_loopback and not ip.is_link_local:seen.add(str(ip))
        except (ValueError,TypeError):pass
    return sorted(seen)


def tick():
    """Scheduler serializes via PostgreSQL advisory transaction lock."""
    with SessionLocal() as db:
        locked=db.execute(text('SELECT pg_try_advisory_xact_lock(590059)')).scalar()
        if not locked:return
        # First reconcile completed jobs; this never creates additional network traffic.
        checks=db.execute(text('''SELECT ch.id,ch.run_id,ch.ip_address,ch.runner_job_id,j.status AS job_status,j.result,j.error,
            r.policy_id FROM security_monitor_checks ch JOIN runner_jobs j ON j.id=ch.runner_job_id
            JOIN security_monitor_runs r ON r.id=ch.run_id WHERE ch.status='queued'
            AND j.status IN ('completed','success','failed','error','cancelled') LIMIT 100''')).mappings().all()
        for check in checks:
            outcome=_interpret(check['job_status'],check['result'])
            db.execute(text('UPDATE security_monitor_checks SET status=:s,result=CAST(:r AS JSONB) WHERE id=:id'),{'s':outcome,'r':json.dumps({'job_status':check['job_status'],'error':check['error']},default=str),'id':check['id']})
            if outcome=='up':
                prior=db.execute(text('''SELECT ch.status FROM security_monitor_checks ch JOIN security_monitor_runs r ON r.id=ch.run_id
                    WHERE r.policy_id=:p AND ch.ip_address=:ip AND ch.id<>:id ORDER BY ch.id DESC LIMIT 1'''),{'p':check['policy_id'],'ip':check['ip_address'],'id':check['id']}).scalar()
                if prior=='down':
                    db.execute(text('''INSERT INTO security_monitor_events(policy_id,run_id,ip_address,event_type)
                      VALUES(:p,:r,:ip,'RECOVERED') ON CONFLICT DO NOTHING'''),{'p':check['policy_id'],'r':check['run_id'],'ip':check['ip_address']})
            elif outcome=='down':
                prior=db.execute(text('''SELECT ch.status FROM security_monitor_checks ch JOIN security_monitor_runs r ON r.id=ch.run_id
                    WHERE r.policy_id=:p AND ch.ip_address=:ip AND ch.id<>:id ORDER BY ch.id DESC LIMIT 1'''),{'p':check['policy_id'],'ip':check['ip_address'],'id':check['id']}).scalar()
                if prior=='down':
                    db.execute(text('''INSERT INTO security_monitor_events(policy_id,run_id,ip_address,event_type)
                      VALUES(:p,:r,:ip,'HOST_UNREACHABLE') ON CONFLICT DO NOTHING'''),{'p':check['policy_id'],'r':check['run_id'],'ip':check['ip_address']})
        # Reconcile targeted TCP port checks, preserving inconclusive states.
        service_jobs=db.execute(text('''SELECT sc.id,sc.run_id,sc.ip_address,sc.port,sc.runner_job_id,
            j.status AS job_status,j.result,r.policy_id FROM security_monitor_service_checks sc
            JOIN runner_jobs j ON j.id=sc.runner_job_id JOIN security_monitor_runs r ON r.id=sc.run_id
            WHERE sc.status='queued' AND j.status IN ('completed','success','failed','error','cancelled') LIMIT 100''')).mappings().all()
        for item in service_jobs:
            states=_service_states(item['result']) if item['job_status'] in ('completed','success') else {}
            observed=states.get(item['port'])
            outcome=observed or 'inconclusive'
            db.execute(text('UPDATE security_monitor_service_checks SET status=:s,observed_state=:o,result=CAST(:v AS JSONB) WHERE id=:id'),
                {'s':outcome,'o':observed,'v':json.dumps({'job_id':item['runner_job_id'],'state':outcome}),'id':item['id']})
            if observed:
                _evaluate_service_policies(db, item, observed)
            if not observed:continue
            prior=db.execute(text('''SELECT sc.observed_state FROM security_monitor_service_checks sc
                JOIN security_monitor_runs r ON r.id=sc.run_id WHERE r.policy_id=:p AND sc.ip_address=:ip
                AND sc.port=:port AND sc.id<>:id AND sc.observed_state IS NOT NULL
                ORDER BY sc.id DESC LIMIT 2'''),{'p':item['policy_id'],'ip':item['ip_address'],'port':item['port'],'id':item['id']}).scalars().all()
            # Two consecutive observations of a new state; require evidence of previous opposite state.
            if len(prior)==2 and prior[0]==observed and prior[1]!=observed:
                details={'port':item['port'],'protocol':'tcp','previous':prior[1],'current':observed,'job_id':item['runner_job_id']}
                db.execute(text('''INSERT INTO security_monitor_events(policy_id,run_id,ip_address,event_type,details)
                    VALUES(:p,:r,:ip,'SERVICE_STATE_CHANGED',CAST(:d AS JSONB)) ON CONFLICT DO NOTHING'''),
                    {'p':item['policy_id'],'r':item['run_id'],'ip':item['ip_address'],'d':json.dumps(details)})
        # Materialize each confirmed event once; no external notifications.
        db.execute(text('''INSERT INTO security_monitor_alerts(event_id,policy_id,severity)
            SELECT e.id,e.policy_id,CASE WHEN e.event_type='HOST_UNREACHABLE' THEN 'warning'
            WHEN e.event_type='RECOVERED' THEN 'info'
            WHEN e.event_type='SERVICE_STATE_CHANGED' THEN 'warning' ELSE 'info' END
            FROM security_monitor_events e WHERE e.event_type <> 'SERVICE_STATE_CHANGED' ON CONFLICT(event_id) DO NOTHING'''))
        # Throttle new probes: at most 5 new Runner jobs per scheduler tick.
        pending=db.execute(text('''SELECT ch.id,ch.ip_address,r.id AS run_id FROM security_monitor_checks ch
            JOIN security_monitor_runs r ON r.id=ch.run_id WHERE r.status='running'
            AND ch.runner_job_id IS NULL ORDER BY ch.id LIMIT 5''')).mappings().all()
        if pending:
            runner=get_online_runner_with_capability('nmap_discovery')
            if runner:
                for item in pending:
                    ip=item['ip_address']
                    job=create_runner_job(runner['runner_id'],'nmap_discovery',ip,{'executor':'nmap_discovery','target':ip,'target_type':'host','provider':'runner','timeout_seconds':30,'exclusions':[],'monitor_run_id':item['run_id']})
                    db.execute(text('UPDATE security_monitor_checks SET runner_job_id=:j WHERE id=:id'),{'j':job['id'],'id':item['id']})
        # One targeted service scan per host; never a broad top-1000 scan.
        service_pending=db.execute(text('''SELECT sc.run_id,sc.ip_address,ARRAY_AGG(sc.port ORDER BY sc.port) AS ports
            FROM security_monitor_service_checks sc JOIN security_monitor_runs r ON r.id=sc.run_id
            WHERE r.status='running' AND sc.runner_job_id IS NULL
            GROUP BY sc.run_id,sc.ip_address ORDER BY sc.run_id,sc.ip_address LIMIT 5''')).mappings().all()
        if service_pending:
            runner=get_online_runner_with_capability('service_discovery')
            if runner:
                for item in service_pending:
                    job=create_runner_job(runner['runner_id'],'service_discovery',item['ip_address'],
                        {'executor':'service_discovery','target':item['ip_address'],'target_type':'host',
                         'monitor_ports':item['ports'],'timeout_seconds':45,'monitor_run_id':item['run_id']})
                    db.execute(text('''UPDATE security_monitor_service_checks SET runner_job_id=:j
                        WHERE run_id=:r AND ip_address=:ip AND runner_job_id IS NULL'''),
                        {'j':job['id'],'r':item['run_id'],'ip':item['ip_address']})
        active=db.execute(text("SELECT id FROM security_monitor_runs WHERE status='running' LIMIT 50")).scalars().all()
        for run_id in active:
            counts=db.execute(text('SELECT status,COUNT(*) AS n FROM security_monitor_checks WHERE run_id=:r GROUP BY status'),{'r':run_id}).all()
            totals=dict(counts)
            services_left=db.execute(text("SELECT COUNT(*) FROM security_monitor_service_checks WHERE run_id=:r AND status='queued'"),{'r':run_id}).scalar()
            if totals.get('queued',0)==0 and not services_left:
                db.execute(text('''UPDATE security_monitor_runs SET status='completed',finished_at=CURRENT_TIMESTAMP,
                    summary=CAST(:s AS JSONB) WHERE id=:r'''),{'r':run_id,'s':json.dumps(totals)})
        # Do not overlap runs; only one job per known host per 60-minute interval.
        due=db.execute(text('''SELECT p.id,p.campaign_id,p.interval_minutes FROM security_monitor_policies p
            WHERE p.enabled=TRUE AND p.mode='light' AND p.authenticated=FALSE AND p.next_run_at<=CURRENT_TIMESTAMP
            AND NOT EXISTS (SELECT 1 FROM security_monitor_runs r WHERE r.policy_id=p.id AND r.status='running')
            ORDER BY p.next_run_at LIMIT 1''')).mappings().first()
        if due:
            baseline=db.execute(text('SELECT id,snapshot FROM attack_campaign_baselines WHERE campaign_id=:c ORDER BY id DESC LIMIT 1'),{'c':due['campaign_id']}).mappings().first()
            runner=get_online_runner_with_capability('nmap_discovery') if baseline else None
            if runner:
                ips=_ips(baseline['snapshot'])[:254]
                if ips:
                    run_id=db.execute(text('INSERT INTO security_monitor_runs(policy_id,baseline_id) VALUES(:p,:b) RETURNING id'),{'p':due['id'],'b':baseline['id']}).scalar_one()
                    for ip in ips:
                        db.execute(text('INSERT INTO security_monitor_checks(run_id,ip_address) VALUES(:r,:ip)'),{'r':run_id,'ip':ip})
                    for ip,ports in _known_ports(baseline['snapshot']).items():
                        if ip not in ips:continue
                        for port in ports:
                            db.execute(text('''INSERT INTO security_monitor_service_checks(run_id,ip_address,port)
                                VALUES(:r,:ip,:port) ON CONFLICT DO NOTHING'''),{'r':run_id,'ip':ip,'port':port})
                    configured=db.execute(text('''SELECT ip_address,port FROM security_service_alert_policies
                        WHERE enabled=TRUE AND protocol='tcp''')).mappings().all()
                    for selected in configured:
                        if selected['ip_address'] in ips:
                            db.execute(text('''INSERT INTO security_monitor_service_checks(run_id,ip_address,port)
                                VALUES(:r,:ip,:port) ON CONFLICT DO NOTHING'''),
                                {'r':run_id,'ip':selected['ip_address'],'port':selected['port']})
                    db.execute(text('UPDATE security_monitor_policies SET next_run_at=CURRENT_TIMESTAMP+(:m * INTERVAL \'1 minute\') WHERE id=:p'),{'m':max(60,due['interval_minutes']),'p':due['id']})
        db.commit()


def _interpret(job_status,result):
    if job_status not in ('completed','success'):return 'inconclusive'
    # A successful Nmap process does not prove host reachability. Only explicit
    # host-level states count; unknown payloads remain inconclusive.
    result=_job_payload(result)
    hosts=result.get('hosts') or result.get('discovered_hosts')
    if not isinstance(hosts,list):return 'inconclusive'
    if any(isinstance(h,dict) and str(h.get('state') or h.get('status') or '').lower() in ('up','online') for h in hosts):return 'up'
    if hosts and all(isinstance(h,dict) and str(h.get('state') or h.get('status') or '').lower() in ('down','offline') for h in hosts):return 'down'
    return 'inconclusive'


def update_alert(campaign_uuid: str, alert_id: int, action: str):
    if action not in ('acknowledge', 'close'):
        raise ValueError('Ação inválida')
    with SessionLocal() as db:
        campaign = _campaign(db, campaign_uuid)
        target = 'acknowledged' if action == 'acknowledge' else 'closed'
        row = db.execute(text('''UPDATE security_monitor_alerts a SET status=:state,
            acknowledged_at=CASE WHEN :state='acknowledged' THEN CURRENT_TIMESTAMP ELSE a.acknowledged_at END,
            closed_at=CASE WHEN :state='closed' THEN CURRENT_TIMESTAMP ELSE a.closed_at END,
            updated_at=CURRENT_TIMESTAMP
            FROM security_monitor_policies p
            WHERE a.policy_id=p.id AND p.campaign_id=:campaign AND a.id=:alert
            AND a.status='open' RETURNING a.id,a.status'''),
            {'state':target,'campaign':campaign['id'],'alert':alert_id}).mappings().first()
        if not row:
            raise ValueError('Alerta inexistente ou não está aberto')
        db.commit()
        return {'success': True, 'alert_id':row['id'], 'status':row['status']}


def _evaluate_service_policies(db, item, observed):
    """Evaluate only one completed observation per policy and run; unknown is not down."""
    policies=db.execute(text("""SELECT * FROM security_service_alert_policies
        WHERE ip_address=:ip AND protocol='tcp' AND port=:port AND enabled=TRUE FOR UPDATE"""),
        {'ip':item['ip_address'],'port':item['port']}).mappings().all()
    for p in policies:
        if p['last_run_id']==item['run_id']:
            continue
        condition=p['condition']
        matches=(observed=='closed' if condition=='unavailable' else observed=='open' if condition=='available' else (p['last_state'] is not None and (observed!=p['last_state'] or p['consecutive']>0)))
        streak=(p['consecutive']+1) if matches and p['last_state']==observed else (1 if matches else 0)
        db.execute(text("""UPDATE security_service_alert_policies SET last_state=:state,
            consecutive=:n,last_run_id=:run,updated_at=CURRENT_TIMESTAMP WHERE id=:id"""),
            {'state':observed,'n':streak,'run':item['run_id'],'id':p['id']})
        active=db.execute(text("""SELECT * FROM security_service_alerts WHERE service_policy_id=:id
            AND status IN ('open','acknowledged') ORDER BY id DESC LIMIT 1 FOR UPDATE"""),{'id':p['id']}).mappings().first()
        if not matches:
            if active:
                db.execute(text("""UPDATE security_service_alerts SET status='closed',resolved_at=CURRENT_TIMESTAMP
                    WHERE id=:id"""),{'id':active['id']})
            continue
        if streak < p['polls']:continue
        if active:
            if p['cooldown_minutes']>0:
                db.execute(text("""UPDATE security_service_alerts SET notification_count=notification_count+1,
                    last_notified_at=CURRENT_TIMESTAMP WHERE id=:id AND
                    last_notified_at<=CURRENT_TIMESTAMP-(:minutes * INTERVAL '1 minute')"""),
                    {'id':active['id'],'minutes':p['cooldown_minutes']})
        else:
            last=db.execute(text("""SELECT status FROM security_service_alerts WHERE service_policy_id=:p ORDER BY id DESC LIMIT 1"""),{'p':p['id']}).scalar()
            if last=='closed' and p['consecutive']>p['polls']:
                continue  # Manually closed; wait for recovery before a new incident.
            db.execute(text("""INSERT INTO security_service_alerts(service_policy_id,monitor_run_id,severity,event_type)
                VALUES(:p,:r,:s,:e)"""),{'p':p['id'],'r':item['run_id'],'s':p['severity'],
                'e':'SERVICE_UNAVAILABLE' if observed=='closed' else 'SERVICE_AVAILABLE'})


def get_service_policy(target_uuid, protocol, port):
    with SessionLocal() as db:
        row=db.execute(text("""SELECT * FROM security_service_alert_policies
            WHERE target_uuid=:t AND protocol=:proto AND port=:port"""),
            {'t':target_uuid,'proto':protocol,'port':port}).mappings().first()
        return dict(row) if row else None


def set_service_policy(target_uuid, ip, protocol, port, payload):
    if protocol!='tcp':raise ValueError('Somente TCP é suportado pelo Monitoring Light')
    condition=payload.get('condition','unavailable')
    severity=payload.get('severity','warning')
    polls=payload.get('polls',2)
    cooldown=payload.get('cooldown_minutes',60)
    enabled=payload.get('enabled',True)
    if condition not in ('unavailable','available','both') or severity not in ('info','warning','critical'):
        raise ValueError('Condição ou severidade inválida')
    if type(polls)!=int or not 1<=polls<=20 or type(cooldown)!=int or not 0<=cooldown<=10080 or type(enabled)!=bool:
        raise ValueError('Valores de configuração inválidos')
    if not 1<=port<=65535:raise ValueError('Porta inválida')
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO security_service_alert_policies
            (target_uuid,ip_address,protocol,port,enabled,condition,polls,cooldown_minutes,severity)
            VALUES(:t,:ip,:proto,:port,:enabled,:condition,:polls,:cooldown,:severity)
            ON CONFLICT(target_uuid,protocol,port) DO UPDATE SET ip_address=EXCLUDED.ip_address,
            enabled=EXCLUDED.enabled,condition=EXCLUDED.condition,polls=EXCLUDED.polls,
            cooldown_minutes=EXCLUDED.cooldown_minutes,severity=EXCLUDED.severity,
            consecutive=0,last_state=NULL,last_run_id=NULL,updated_at=CURRENT_TIMESTAMP
            RETURNING *"""),{'t':target_uuid,'ip':ip,'proto':protocol,'port':port,'enabled':enabled,
            'condition':condition,'polls':polls,'cooldown':cooldown,'severity':severity}).mappings().one()
        db.commit()
        return dict(row)


def list_service_alerts():
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT a.*,p.target_uuid,p.ip_address,p.port,p.protocol,p.condition
            FROM security_service_alerts a JOIN security_service_alert_policies p ON p.id=a.service_policy_id
            ORDER BY a.id DESC LIMIT 500""")).mappings().all()
        return [dict(row) for row in rows]


def service_alert_action(alert_id,action):
    if action not in ('acknowledge','close'):raise ValueError('Ação inválida')
    with SessionLocal() as db:
        state='acknowledged' if action=='acknowledge' else 'closed'
        row=db.execute(text("""UPDATE security_service_alerts SET status=:s,
            acknowledged_at=CASE WHEN :s='acknowledged' THEN CURRENT_TIMESTAMP ELSE acknowledged_at END,
            resolved_at=CASE WHEN :s='closed' THEN CURRENT_TIMESTAMP ELSE resolved_at END
            WHERE id=:id AND status='open' RETURNING id,status"""),
            {'s':state,'id':alert_id}).mappings().first()
        if not row:raise ValueError('Alerta inexistente ou já tratado')
        db.commit()
        return dict(row)
