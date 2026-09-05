
from magi_runner.executors import credential_validate as cv
import inspect

def test_winrm_creates_evidence_in_same_invoke_command():
    src=inspect.getsource(cv._winrm_validate)
    assert "MAGI esteve aqui" in src
    assert "Data/Hora:" in src
    assert "Invoke-Command" in src
    assert "evidence_created" in src
    assert "evidence_verified" in src

def test_smb_access_and_evidence_are_one_validation_flow():
    src=inspect.getsource(cv._smb_validate)
    assert "IPC$" in src
    assert "C$" in src
    assert "MAGI_EVIDENCE.txt" in src
    assert "MAGI esteve aqui" in src
    assert "evidence_error" in src

def test_executor_does_not_open_second_evidence_connection():
    src=inspect.getsource(cv.CredentialValidateExecutor.run)
    assert "_create_benign_evidence(" not in src
    assert "_winrm_validate(target,cred,timeout_seconds,payload)" in src
    assert "_smb_validate(target,cred,timeout_seconds,payload)" in src
