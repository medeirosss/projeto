from unittest.mock import patch
from magi_runner.executors.nuclei import NucleiExecutor

def _job():
    return {"target":"http://192.168.0.100","payload":{"target":"http://192.168.0.100","template":"http/cves/"}}

def test_engine_unavailable_is_not_target_unreachable(tmp_path):
    with patch("magi_runner.executors.nuclei._find_nuclei",return_value=None):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["finding"]["status"]=="not_evaluated"
    assert r.metadata["evidence"]["reason"]=="engine_unavailable"

def test_template_unavailable_is_not_target_unreachable(tmp_path):
    fake=tmp_path/"nuclei.exe"; fake.write_text("x")
    with patch("magi_runner.executors.nuclei._find_nuclei",return_value=str(fake)):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["finding"]["status"]=="not_evaluated"
    assert r.metadata["evidence"]["reason"]=="template_unavailable"
