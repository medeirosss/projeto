from magi_runner.executors.atomic import _classify_atomic_outcome
from magi_runner.executors.base import ExecutionResult

def result(stdout="",stderr="",status="success",exit_code=0):
    return ExecutionResult(status=status,exit_code=exit_code,stdout=stdout,stderr=stderr,started_at="x",finished_at="y",duration_seconds=1.0,metadata={})

def test_success_without_confirmation_is_unverified():
    state,signals=_classify_atomic_outcome(result("Done executing test"),True); assert state=="executed_unverified"; assert signals==[]

def test_antimalware_signal_is_prevented():
    state,signals=_classify_atomic_outcome(result("Não foi possível concluir a operação porque o arquivo contém um vírus ou software possivelmente indesejado."),True); assert state=="prevented"; assert "antimalware" in signals

def test_internal_powershell_error_is_not_confirmed():
    state,signals=_classify_atomic_outcome(result("FullyQualifiedErrorId : Something,Write-Error"),True); assert state=="not_confirmed"

def test_failed_runner_is_error():
    state,signals=_classify_atomic_outcome(result(status="failed",exit_code=1),True); assert state=="error"
