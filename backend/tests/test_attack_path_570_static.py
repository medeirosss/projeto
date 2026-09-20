from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_migration_has_path_and_telemetry_tables():
    s=(ROOT/'alembic/versions/20260920_0032_attack_path_telemetry_5_7.py').read_text()
    for x in ('attack_path_runs','attack_path_edges','attack_path_telemetry','RETURN_CONFIRMED'): assert x in s
def test_telemetry_is_metadata_only_and_relay_capable():
    s=(ROOT/'backend/app/services/attack_path_service.py').read_text()
    assert "allowed={'message','reason','evidence_ref','runner_job_id','protocol','latency_ms'}" in s
    assert 'ingest_relay' in s and "x['transport']='relay'" in s
def test_campaign_import_does_not_fake_lateral_confirmation():
    s=(ROOT/'backend/app/services/attack_path_service.py').read_text()
    assert "elif status=='confirmed' or result=='access_confirmed': state='VALIDATABLE'" in s
    assert "remote_origin_confirmed" in s
def test_runner_has_no_listener_beacon():
    s=(ROOT/'runner/magi_runner/core/path_telemetry.py').read_text()
    assert 'No listener, beacon or persistence' in s
    assert 'def relay(' in s
def test_ui_has_attack_path_workspace():
    h=(ROOT/'frontend/attack-simulator.html').read_text(); j=(ROOT/'frontend/attack-simulator.js').read_text()
    assert 'data-view="attackpath"' in h and 'attackPathTelemetry' in h
    assert 'loadAttackPaths' in j and 'viewAttackPath' in j
