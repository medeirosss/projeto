from pathlib import Path

def test_dhcp_executor_uses_controlled_trustedhosts_and_negotiate():
    p=Path(__file__).parents[1]/'magi_runner'/'executors'/'windows_dhcp_inventory.py'
    s=p.read_text(encoding='utf-8')
    assert "TrustedHosts" in s
    assert "-Authentication Negotiate" in s
    assert "$items+$server" in s
    assert "if($trustedChanged)" in s
    assert "-Value ($oldTrusted -as [string])" in s
    assert "-Value '*'" not in s and '-Value "*"' not in s
