
from magi_runner.executors import credential_validate as cv

def test_failure_status_trustedhosts():
    assert cv._failure_status("winrm","MAGI_WINRM_STAGE=trustedhosts_update; Access denied",1) == "trustedhosts_failed"

def test_failure_status_timeout():
    assert cv._failure_status("winrm","MAGI_WINRM_STAGE=timeout; WinRM validation timed out.",1) == "timeout"

def test_failure_status_authentication():
    assert cv._failure_status("winrm","Access is denied",1) == "authentication_failed"

def test_failure_status_service_unavailable():
    assert cv._failure_status("winrm","WinRM cannot complete the operation because the WinRM service is unavailable",1) == "service_unavailable"

def test_winrm_contract_contains_negotiate_and_cleanup():
    import inspect
    src=inspect.getsource(cv._winrm_validate)
    assert "-Authentication Negotiate" in src
    assert "Restore-MagiTrustedValue" in src
    assert "finally" in src
