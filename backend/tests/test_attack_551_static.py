from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_backend_persists_runner_logs():
    s=(ROOT/"backend/app/repositories/validation_repository.py").read_text()
    assert "evidence['logs']" in s
    assert "'stdout': (result or {}).get('stdout')" in s
    assert "'stderr': (result or {}).get('stderr')" in s

def test_log_endpoint_exists_and_sanitizes():
    r=(ROOT/"backend/app/routers/attack_simulator.py").read_text()
    s=(ROOT/"backend/app/services/attack_simulator_service.py").read_text()
    assert '@router.get("/history/{execution_id}/log")' in r
    assert "def attack_execution_log" in s
    assert "REDACTED_KERBEROS_MATERIAL" in s

def test_snmp_uses_credential_profile():
    s=(ROOT/"backend/app/services/attack_simulator_service.py").read_text()
    start=s.index('"task_key": "MAGI-M-ATK-NET-001"')
    block=s[start:start+2200]
    assert '"credential_required": True' in block

def test_history_has_log_action_and_tabs():
    h=(ROOT/"frontend/attack-simulator.html").read_text()
    j=(ROOT/"frontend/attack-simulator.js").read_text()
    assert 'attackHistoryLogPanel' in h
    assert 'data-log-tab="stdout"' in h
    assert 'data-log-tab="stderr"' in h
    assert '>Log</button>' in j
    assert "openHistoryLog" in j
