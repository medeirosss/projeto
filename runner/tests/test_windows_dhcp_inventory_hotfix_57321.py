import json
from magi_runner.executors import windows_dhcp_inventory as mod
from magi_runner.executors.base import ExecutionResult


def _job():
    return {"target":"dhcp01.lab.local","payload":{"dhcp_server":"dhcp01.lab.local","credential":{"username":"svc","domain":"LAB","secret":"x"}}}


def test_failed_dhcp_execution_does_not_raise_unboundlocal(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.shutil, "which", lambda _: "powershell.exe")
    monkeypatch.setattr(mod, "run_subprocess", lambda *a, **k: ExecutionResult(status="failed", exit_code=1, stdout="", stderr="Access denied", started_at="x", finished_at="y", duration_seconds=0.1, metadata={}))
    result=mod.WindowsDhcpInventoryExecutor().run(_job(), str(tmp_path), 30)
    assert result.status == "failed"
    assert result.metadata["scope_count"] == 0
    assert result.metadata["lease_count"] == 0
    assert result.metadata["active_lease_count"] == 0
    assert result.metadata["scopes"] == []


def test_successful_dhcp_execution_keeps_counts(monkeypatch, tmp_path):
    payload={"scopes":[{"scope_id":"192.168.0.0","active_leases":1}],"leases":[{"ip_address":"192.168.0.10","address_state":"Active"}]}
    monkeypatch.setattr(mod.shutil, "which", lambda _: "powershell.exe")
    monkeypatch.setattr(mod, "run_subprocess", lambda *a, **k: ExecutionResult(status="success", exit_code=0, stdout=json.dumps(payload), stderr="", started_at="x", finished_at="y", duration_seconds=0.1, metadata={}))
    result=mod.WindowsDhcpInventoryExecutor().run(_job(), str(tmp_path), 30)
    assert result.status == "success"
    assert result.metadata["scope_count"] == 1
    assert result.metadata["lease_count"] == 1
    assert result.metadata["active_lease_count"] == 1
