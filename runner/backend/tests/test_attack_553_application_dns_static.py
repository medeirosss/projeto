from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_application_runner_uses_ip_rhosts_and_vhost():
    s=(ROOT/"runner/magi_runner/executors/metasploit.py").read_text()
    assert "_resolve_application_host" in s
    assert 'target = application_resolution["resolved_ip"]' in s
    assert 'set VHOST' in s and "application['host']" in s
    assert '"resolved_ip": application_resolution["resolved_ip"]' in s
    assert '"dns_resolution": application_resolution["dns_resolution"]' in s
