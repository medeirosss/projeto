from unittest.mock import patch
from magi_runner.executors.nuclei import NucleiExecutor

def _job():
    return {"target":"192.168.0.100","payload":{
        "target":"192.168.0.100","template":"http/cves/","profile_name":"CVE HTTP/HTTPS",
        "protocol":"http","ports":[80,443]
    }}

def test_template_unavailable_is_not_target_unreachable(tmp_path):
    exe=tmp_path/"nuclei.exe"; exe.write_text("x")
    cap={"binary_path":str(exe),"templates_path":str(tmp_path/"templates"),"runtime_policy":"fixed_bundled",
         "runtime_integrity":{"status":"ok"},"searched_paths":[str(exe)]}
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=cap):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["finding"]["status"]=="not_evaluated"
    assert r.metadata["evidence"]["reason"]=="template_unavailable"
    assert r.metadata["executed_real_test"] is False

def test_runtime_integrity_failure_is_not_evaluated(tmp_path):
    exe=tmp_path/"nuclei.exe"; exe.write_text("x")
    templates=tmp_path/"templates"; (templates/"http"/"cves").mkdir(parents=True)
    cap={"binary_path":str(exe),"templates_path":str(templates),"runtime_policy":"fixed_bundled",
         "runtime_integrity":{"status":"failed"},"searched_paths":[str(exe)]}
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=cap):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["evidence"]["reason"]=="runtime_integrity_failed"
