from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def test_migration_and_provider_tables():
    s=read('alembic/versions/20260921_0034_windows_dhcp_campaign_coverage.py')
    assert 'attack_campaign_dhcp_leases' in s and 'attack_campaign_coverage' in s and 'dhcp_credential_id' in s
def test_dhcp_runner_is_fixed_read_only_provider():
    s=read('runner/magi_runner/executors/windows_dhcp_inventory.py')
    assert 'Get-DhcpServerv4Scope' in s and 'Get-DhcpServerv4Lease' in s
    assert 'Set-Dhcp' not in s and 'Remove-Dhcp' not in s and 'Add-Dhcp' not in s
def test_dhcp_job_secret_is_transient():
    s=read('backend/app/services/attack_campaign_service.py')
    assert "'credential_id':int(c['dhcp_credential_id'])" in s
    assert "'windows_dhcp_inventory'" in s
    assert "'secret'" not in s[s.index('def _queue_windows_dhcp_inventory'):s.index('def _refresh_campaign_coverage')]
def test_coverage_semantics():
    s=read('backend/app/services/attack_campaign_service.py')
    assert 'KNOWN_NOT_REACHED' in s and 'known_asset_coverage_pct' in s
def test_ui_explains_dhcp_not_reachability():
    s=read('frontend/attack-simulator.js')+read('frontend/attack-simulator.html')
    assert 'Coverage Intelligence' in s and 'DHCP lease não significa host online' in s
def test_runner_version(): assert '2.21.0' in read('runner/magi_runner/core/version.py')
