from magi_runner.core.state import LocalState


def test_result_spool_persists_and_replaces(tmp_path):
    state = LocalState(tmp_path)
    state.spool_result("616", {"status": "target_unreachable", "v": 1})
    assert state.list_spooled_results()[0]["job_id"] == "616"

    state.spool_result("616", {"status": "target_unreachable", "v": 2})
    items = state.list_spooled_results()
    assert len(items) == 1
    assert items[0]["result"]["v"] == 2

    state.remove_spooled_result("616")
    assert state.list_spooled_results() == []


def test_job_not_completed_until_ack(tmp_path):
    state = LocalState(tmp_path)
    state.spool_result("616", {"status": "target_unreachable"})
    assert not state.is_completed("616")

    state.remove_spooled_result("616")
    state.mark_completed("616")
    assert state.is_completed("616")
