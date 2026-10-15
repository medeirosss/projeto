from pathlib import Path
P=Path(__file__).parents[1]/'magi_runner/executors/windows_dhcp_inventory.py'
S=P.read_text(encoding='utf-8')
def test_remote_dhcp_cmdlets_execute_locally():
    assert 'Get-DhcpServerv4Scope -ErrorAction Stop' in S
    assert 'Get-DhcpServerv4Lease -ScopeId' in S
    assert 'Get-DhcpServerv4Scope -ComputerName' not in S
    assert 'Get-DhcpServerv4Lease -ComputerName' not in S
def test_module_localization_errors_are_warnings_if_cmdlets_exist():
    assert 'Import-Module DhcpServer -ErrorAction SilentlyContinue' in S
    assert "'warnings':warnings" in S
    assert 'DHCP_MODULE_UNAVAILABLE' in S
