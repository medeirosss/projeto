from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def txt(p): return (ROOT/p).read_text(encoding='utf-8')
def test_deep_inventory_two_failure_gate():
    s=txt('backend/app/repositories/deep_inventory_repository.py')
    assert "COUNT(*) FROM deep_inventory_jobs" in s and ") < 2" in s
    assert "djf.finished_at >= COALESCE(s.last_run_at" in s
def test_scan_now_dispatches_real_job():
    s=txt('backend/app/services/asset_rescan_service.py')
    assert "execute_scan(host_scan,'asset_rescan')" in s
    assert "runner_job_id" in s and "run_uuid" in s
def test_rescan_does_not_cleanup_full_scan():
    s=txt('backend/app/services/target_service.py')
    assert 'run.get("trigger_type") != "asset_rescan"' in s
def test_smb_anonymous_is_zero_credential():
    s=txt('backend/app/services/attack_simulator_service.py')
    assert 'MAGI-ATK-END-005' in s and 'smb_anonymous_session' in s
    block=s[s.index('MAGI-ATK-END-005'):s.index('MAGI-ATK-END-005')+1200]
    assert '"credential_requirement":"NONE"' in block
def test_runner_supports_smb_anonymous():
    s=txt('runner/magi_runner/executors/attack_simulation.py')
    assert '_smb_anonymous_session' in s and 'credential_used":False' in s
def test_knowledge_003_maps_anonymous():
    d=json.loads(txt('backend/app/data/attack_knowledge_2026.09.003.json'))
    a=next(x for x in d['attacks'] if x['name']=='SMB Anonymous Session')
    assert a['techniques'][0]['technique_key']=='MAGI-ATK-END-005'
    assert a['techniques'][0]['credential_requirement']=='NONE'
