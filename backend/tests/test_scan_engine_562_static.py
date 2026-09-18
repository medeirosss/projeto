from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def test_562_version(): assert read('VERSION').strip()=='5.6.2.1'
def test_multi_credential_schema():
 s=read('alembic/versions/20260918_0030_scan_engine_v2_attack_exposure.py'); assert 'discovery_scan_credentials' in s and 'discovery_scan_exclusions' in s
def test_asset_rescan_identity_guard():
 s=read('backend/app/services/asset_rescan_service.py'); assert "'ip_only':'NEVER_CONFIRMED'" in s and 'DO_NOT_UPDATE' in s
def test_attack_exposure():
 s=read('backend/app/services/attack_exposure_service.py'); assert 'asset_attack_exposure' in s and 'simulation_count' in s
def test_ui_attack_simulation_buttons():
 s=read('frontend/targets.html'); assert '<th>Ataques</th>' in s and '<th>Simulações</th>' in s
def test_runner_exclusions(): assert '--exclude' in read('runner/magi_runner/executors/nmap_discovery.py')
def test_local_windows_supported(): assert 'windows_local' in read('runner/magi_runner/executors/credential_validate.py')
