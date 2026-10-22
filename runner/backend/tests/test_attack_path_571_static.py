from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_campaign_sync_and_winrm_proof_present():
    s=(ROOT/'backend/app/services/attack_path_service.py').read_text(encoding='utf-8')
    assert 'def sync_from_campaign' in s
    assert "MAGI-ATK-END-101" in s
    assert "p.get('protocol')!='winrm'" in s
    assert "state='EXECUTING'" in s

def test_result_ingestion_builds_return_telemetry():
    s=(ROOT/'backend/app/services/attack_path_service.py').read_text(encoding='utf-8')
    assert 'def ingest_path_validation_result' in s
    for event in ['RELAY_STARTED','RELAY_RETURNED','RETURN_CONFIRMED']:
        assert event in s
    assert "new_state='RETURN_CONFIRMED' if confirmed else 'BLOCKED'" in s

def test_runner_service_hooks_campaign_and_attack_results():
    s=(ROOT/'backend/app/services/runner_service.py').read_text(encoding='utf-8')
    assert 'sync_from_campaign' in s
    assert 'ingest_path_validation_result' in s

def test_runner_version():
    s=(ROOT/'runner/magi_runner/core/version.py').read_text(encoding='utf-8')
    assert '2.21.0' in s
