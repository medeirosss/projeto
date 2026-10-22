from pathlib import Path
import pytest

from magi_runner.executors.metasploit import TECHNIQUES, _target, _safe_console_value, _extract, _normalized_status

def test_four_curated_techniques():
    assert set(TECHNIQUES) == {
        "MAGI-M-ATK-END-001","MAGI-M-ATK-AD-001",
        "MAGI-M-ATK-APP-001","MAGI-M-ATK-NET-001"
    }
    assert {x["category"] for x in TECHNIQUES.values()} == {
        "Endpoint","Active Directory","Application","Network Node"
    }

def test_console_injection_rejected():
    with pytest.raises(ValueError):
        _safe_console_value("public; exit", "community")
    with pytest.raises(ValueError):
        _target("192.168.0.1; shell")

def test_smb_output_normalization_from_lab_shape():
    out="""[*] 192.168.0.100:445 - SMB Detected (versions: 2, 3) (preferred dialect: SMB 3.1.1) (compression capabilities: LZNT1) (encryption capabilities: AES-256-GCM) (signatures: required) (authentication domain: LABDANIEL)
[+] 192.168.0.100:445 - Host is running Version 10.0.20348 (likely Windows Server 2022)
[*] 192.168.0.100 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed"""
    ev=_extract(out,"MAGI-M-ATK-END-001","192.168.0.100")
    assert ev["smb_versions"] == ["2","3"]
    assert ev["os_build"] == "10.0.20348"
    assert ev["authentication_domain"] == "LABDANIEL"
    status,result=_normalized_status("MAGI-M-ATK-END-001",out,"warning: recog regex",0,ev)
    assert status=="success" and result=="SUCCESS"
