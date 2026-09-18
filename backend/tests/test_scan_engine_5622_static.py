from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def test_magi_attack_credential_executor_uses_attack_simulation_job_type():
    s=read('backend/app/services/validation_engine_service.py')
    assert 'task.get("repository_key")=="magi_attack"' in s
    assert '"attack_simulation"' in s

def test_asset_simulation_reuses_confirmed_compatible_credential():
    s=read('backend/app/routers/targets.py')
    assert 'target.get("credentials")' in s
    assert 'required=="windows"' in s
    assert 'required=="snmp"' in s
    assert 'required=="ssh"' in s
    assert 'last_successful_credential_id' in s

def test_runner_injects_secret_for_attack_simulation():
    s=read('backend/app/services/runner_service.py')
    assert '"attack_simulation"' in s and 'payload["credential"]' in s
