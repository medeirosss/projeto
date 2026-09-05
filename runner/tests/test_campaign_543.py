
from pathlib import Path
from magi_runner.executors import credential_validate as cv
import inspect

def test_campaign_evidence_helper_exists():
    assert hasattr(cv, "_create_benign_evidence")

def test_campaign_evidence_contract_winrm():
    src=inspect.getsource(cv._create_benign_evidence)
    assert "MAGI_EVIDENCE.txt" in src
    assert "-Authentication Negotiate" in src
    assert "TrustedHosts" in src
    assert "evidence_verified" in src

def test_campaign_evidence_does_not_run_when_not_requested():
    result=cv._create_benign_evidence("192.0.2.1",{}, "winrm", {"create_benign_evidence":False}, 5)
    assert result["evidence_requested"] is False
    assert result["evidence_created"] is False

def test_campaign_evidence_smb_support_is_present():
    src=inspect.getsource(cv._create_benign_evidence)
    assert "C$" in src
    assert "New-PSDrive" in src
