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


def status(campaign_uuid):
    with SessionLocal() as db:
        campaign=_campaign(db,campaign_uuid)
        policy=db.execute(text('SELECT * FROM security_monitor_policies WHERE campaign_id=:c'),{'c':campaign['id']}).mappings().first()
        if not policy:return {'success':True,'enabled':False,'interval_minutes':60,'mode':'light','authenticated':False,'confirmations':2,'runs':[],'events':[]}
        runs=db.execute(text('SELECT id,baseline_id,status,started_at,finished_at,summary FROM security_monitor_runs WHERE policy_id=:p ORDER BY id DESC LIMIT 20'),{'p':policy['id']}).mappings().all()
        events=db.execute(text('SELECT id,run_id,ip_address,event_type,details,created_at FROM security_monitor_events WHERE policy_id=:p ORDER BY id DESC LIMIT 100'),{'p':policy['id']}).mappings().all()
        return {'success':True,'enabled':policy['enabled'],'interval_minutes':policy['interval_minutes'],'mode':policy['mode'],'authenticated':policy['authenticated'],'confirmations':policy['confirmations'],'next_run_at':policy['next_run_at'],'runs':[dict(r) for r in runs],'events':[dict(r) for r in events]}


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
        active=db.execute(text("SELECT id FROM security_monitor_runs WHERE status='running' LIMIT 50")).scalars().all()
        for run_id in active:
            counts=db.execute(text('SELECT status,COUNT(*) AS n FROM security_monitor_checks WHERE run_id=:r GROUP BY status'),{'r':run_id}).all()
            totals=dict(counts)
            if totals.get('queued',0)==0:
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
                    db.execute(text('UPDATE security_monitor_policies SET next_run_at=CURRENT_TIMESTAMP+(:m * INTERVAL \'1 minute\') WHERE id=:p'),{'m':max(60,due['interval_minutes']),'p':due['id']})
        db.commit()


def _interpret(job_status,result):
    if job_status not in ('completed','success'):return 'inconclusive'
    # A successful Nmap process does not prove host reachability. Only explicit
    # host-level states count; unknown payloads remain inconclusive.
    if not isinstance(result,dict):return 'inconclusive'
    hosts=result.get('hosts') or result.get('discovered_hosts')
    if not isinstance(hosts,list):return 'inconclusive'
    if any(isinstance(h,dict) and str(h.get('state') or h.get('status') or '').lower() in ('up','online') for h in hosts):return 'up'
    if hosts and all(isinstance(h,dict) and str(h.get('state') or h.get('status') or '').lower() in ('down','offline') for h in hosts):return 'down'
    return 'inconclusive'
