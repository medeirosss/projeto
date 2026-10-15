from pathlib import Path
BASE=Path(__file__).resolve().parents[2]
def test_dhcp_cache_routes():
    s=(BASE/'backend/app/routers/settings.py').read_text()
    assert '/settings/dhcp/cache/{integration_id}' in s
    assert "module='dhcp_cache'" in s
    assert 'snapshot.get("leases")' in s

def test_scan_pipeline():
    s=(BASE/'backend/app/routers/settings.py').read_text()
    assert '"service_discovery_enabled":True' in s
    assert '"deep_inventory_enabled":True' in s
    assert 'repo.set_scan_credentials' in s

def test_coverage_ui():
    s=(BASE/'frontend/attack-simulator.js').read_text()
    assert 'Cobertura DHCP:' in s
    assert "renderCampaignTab(id,'coverage',c)" in s

def test_cache_ui():
    s=(BASE/'frontend/settings.js').read_text()
    assert 'renderDhcpSnapshot' in s
    assert 'Falha na atualização:' in s
