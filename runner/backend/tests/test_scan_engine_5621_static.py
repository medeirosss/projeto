from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def test_counts_from_asset_exposure():
 s=read('backend/app/repositories/target_repository.py'); assert 'AS attack_count' in s and 'AS simulation_count' in s
def test_contextual_simulation_execute():
 s=read('backend/app/routers/targets.py'); assert '/simulations/{technique_key}/execute' in s and 'execute_task' in s
def test_scan_credential_checkboxes():
 h=read('frontend/targets.html'); j=read('frontend/targets.js'); assert 'scanCredentialChecklist' in h and 'scan-credential-check' in j
def test_scan_exclusion_panel():
 h=read('frontend/targets.html'); assert 'scanExclusionInput' in h and 'scanExclusionList' in h
def test_last_rescan_visible():
 h=read('frontend/targets.html'); j=read('frontend/targets.js'); assert 'Último Scan' in h and 'last_rescan_at' in j
def test_asset_log_ui():
 j=read('frontend/targets.js'); assert 'loadAssetSimulationLog' in j and 'Erros / Avisos' in j and 'Evidência' in j
