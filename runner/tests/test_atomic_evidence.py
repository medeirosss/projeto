from magi_runner.executors.atomic import _classify_remote_atomic, _atomic_exit_code, _execution_section

def test_success_without_confirmation_is_unverified():
    state, signals, atomic_exit = _classify_remote_atomic(
        "MAGI_EXECUTE_BEGIN\nDone executing test\nExit code: 0\nMAGI_EXECUTE_END", "success", 0
    )
    assert state == "executed_unverified"
    assert signals == []
    assert atomic_exit == 0

def test_antimalware_signal_is_prevented():
    state, signals, atomic_exit = _classify_remote_atomic(
        "MAGI_EXECUTE_BEGIN\narquivo contém um vírus ou software possivelmente indesejado.\nExit code: 0\nMAGI_EXECUTE_END",
        "success", 0
    )
    assert state == "prevented"
    assert "antimalware" in signals

def test_missing_dependency_is_not_success():
    state, signals, atomic_exit = _classify_remote_atomic(
        "MAGI_EXECUTE_BEGIN\n'gsecdump.exe' is not recognized as an internal or external command\nExit code: 1\nMAGI_EXECUTE_END",
        "success", 0
    )
    assert state == "dependency_missing"
    assert atomic_exit == 1

def test_atomic_inner_exit_code_overrides_wrapper_semantics():
    state, signals, atomic_exit = _classify_remote_atomic(
        "MAGI_EXECUTE_BEGIN\nExit code: 1\nDone executing test\nMAGI_EXECUTE_END",
        "success", 0
    )
    assert state == "not_confirmed"
    assert atomic_exit == 1

def test_execution_section_does_not_use_prereq_exit_codes():
    output = "MAGI_PREREQ_BEGIN\nExit code: 1\nMAGI_PREREQ_END\nMAGI_EXECUTE_BEGIN\nExit code: 0\nMAGI_EXECUTE_END"
    assert _atomic_exit_code(output) == 0
