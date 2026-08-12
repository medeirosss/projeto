from magi_runner.executors.atomic import AtomicExecutor
from magi_runner.executors.base import ExecutionResult
import magi_runner.executors.atomic as atomic_module


def test_atomic_marks_real_execution_and_scope(monkeypatch):
    class FakePowerShell:
        def run(self, job, workdir, timeout_seconds):
            return ExecutionResult(
                status='success', exit_code=0, stdout='ok', stderr='',
                started_at='2026-08-12T00:00:00+00:00',
                finished_at='2026-08-12T00:00:01+00:00',
                duration_seconds=1.0, metadata={'args':['powershell']}
            )
    monkeypatch.setattr(atomic_module, 'PowerShellExecutor', FakePowerShell)
    result = AtomicExecutor().run({
        'target': '192.168.0.100',
        'payload': {'technique_id':'T1003.003','atomic_test_number':1,'target_host':'192.168.0.100'}
    }, '.', 120)
    assert result.metadata['executed_real_test'] is True
    assert result.metadata['confirmation_status'] == 'executed_unverified'
    assert result.metadata['execution_scope'] == 'runner_local'
    assert result.metadata['requested_target'] == '192.168.0.100'
    assert result.stdout == 'ok'
