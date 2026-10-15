from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from magi_runner.executors.windows_dhcp_inventory import WindowsDhcpInventoryExecutor


def test_remote_script_checks_localizations_and_restores_culture(tmp_path):
    captured = {}
    def run(argv, workdir, timeout):
        import base64
        captured['script'] = base64.b64decode(argv[-1]).decode('utf-16le')
        return SimpleNamespace(status='success', stdout='{"scopes":[],"leases":[],"warnings":[]}', stderr='', metadata={})
    job={'target':'192.168.0.100','payload':{'credential':{'username':'administrator','domain':'labdaniel','secret':'dummy'}}}
    with patch('magi_runner.executors.windows_dhcp_inventory.shutil.which',return_value='powershell.exe'), patch('magi_runner.executors.windows_dhcp_inventory.run_subprocess',side_effect=run):
        result=WindowsDhcpInventoryExecutor().run(job,str(tmp_path),90)
    assert result.status=='success'
    for expected in ('pt-BR','en-US','CurrentUICulture=$previousCulture','Get-DhcpServerv4Lease','TrustedHosts','Invoke-Command'):
        assert expected in captured['script']
