from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def test_credential_set_is_persisted_and_sequential():
    s=read('backend/app/services/attack_campaign_service.py')
    assert 'windows_credential_ids' in s
    assert "max_attempts':1" in s
    assert 'next((cid for cid in _windows_credentials(c) if cid not in attempted),None)' in s
    assert "if active: continue" in s
def test_ssh_removed_from_campaign_ui():
    h=read('frontend/attack-simulator.html')
    assert 'vec_ssh' not in h
    assert 'Windows Credential Set' in h
def test_network_intelligence_lldp_cdp():
    s=read('runner/magi_runner/executors/campaign_probe.py')
    assert 'lldpRemSysName' in s and 'Cisco-CDP-MIB' in s
    assert '_snmp_neighbors' in s
    j=read('frontend/attack-simulator.js')
    assert 'Network Intelligence' in j and 'snmp_neighbors' in j
def test_runner_572_version():
    assert '2.21.0' in read('runner/magi_runner/core/version.py')
