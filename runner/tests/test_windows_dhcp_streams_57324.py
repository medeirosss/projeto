import json
from types import SimpleNamespace
from unittest.mock import patch
from magi_runner.executors.windows_dhcp_inventory import WindowsDhcpInventoryExecutor, _decode_powershell_stream, _extract_json

CLIXML = '#< CLIXML\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Import-Module : DhcpServerMigration.psd1 _x000D__x000A_ nonfatal</S></Objs>'

def test_clixml_decoding():
    clean, messages = _decode_powershell_stream(CLIXML)
    assert clean == ''
    assert 'DhcpServerMigration.psd1' in messages[0]
    assert '\r\n' in messages[0]

def test_json_after_noise():
    assert _extract_json('progress\n{"scopes":[],"leases":[],"warnings":[]}')['leases'] == []

def test_success_with_nonfatal_clixml(tmp_path):
    payload = '{"scopes":[],"leases":[{"address_state":"Active"}],"warnings":[]}'
    result = SimpleNamespace(status='success', stdout='progress\n'+payload, stderr=CLIXML, metadata={})
    job = {'target':'dhcp01','payload':{'credential':{'username':'admin','secret':'test'}}}
    with patch('magi_runner.executors.windows_dhcp_inventory.shutil.which',return_value='powershell.exe'), patch('magi_runner.executors.windows_dhcp_inventory.run_subprocess',return_value=result):
        output = WindowsDhcpInventoryExecutor().run(job,str(tmp_path),90)
    assert output.status == 'success'
    assert output.metadata['active_lease_count'] == 1
    assert output.metadata['warning_count'] == 1
    assert output.stderr == ''
    assert json.loads(output.stdout)['lease_count'] == 1

def test_missing_json_is_error(tmp_path):
    result = SimpleNamespace(status='success',stdout='only progress',stderr='',metadata={})
    job={'target':'dhcp01','payload':{'credential':{'username':'admin','secret':'test'}}}
    with patch('magi_runner.executors.windows_dhcp_inventory.shutil.which',return_value='powershell.exe'), patch('magi_runner.executors.windows_dhcp_inventory.run_subprocess',return_value=result):
        output=WindowsDhcpInventoryExecutor().run(job,str(tmp_path),90)
    assert output.status == 'error'
    assert 'No valid DHCP JSON' in output.stderr
