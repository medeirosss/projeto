from pathlib import Path
R=Path(__file__).resolve().parents[2]
def read(p): return (R/p).read_text(encoding='utf-8')
def test_version(): assert read('VERSION').strip()=='5.7.3.2'
def test_dhcp_validation_api():
    s=read('backend/app/routers/settings.py'); assert '/settings/dhcp/validate' in s and 'windows_dhcp_inventory' in s
def test_dhcp_validation_summary():
    s=read('runner/magi_runner/executors/windows_dhcp_inventory.py'); assert 'scope_count' in s and 'active_lease_count' in s and 'Get-DhcpServerv4ScopeStatistics' in s
def test_dhcp_feeds_campaign_discovery():
    s=read('backend/app/services/attack_campaign_service.py'); assert 'dhcp_known' in s and "active%" in s and 'ordered=dhcp_known+' in s
def test_ui_requires_validation_before_save():
    s=read('frontend/settings.js'); assert "Validando DHCP pelo Runner" in s and "DHCP conectado com sucesso" in s
