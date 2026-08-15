from types import SimpleNamespace
from unittest.mock import patch
from magi_runner.executors.nuclei import NucleiExecutor

def job(tmp_path=None):
    payload={"target":"http://192.168.0.100","template":"http/test.yaml","executor":"nuclei"}
    if tmp_path is not None:
        template_root=tmp_path/"templates"
        (template_root/"http").mkdir(parents=True,exist_ok=True)
        (template_root/"http"/"test.yaml").write_text("id: test")
        payload["nuclei_templates_path"]=str(template_root)
    return {"target":"http://192.168.0.100","payload":payload}

def test_nuclei_match_detected(tmp_path):
    out='{"template-id":"CVE-TEST","matched-at":"http://192.168.0.100"}\n'
    cp=SimpleNamespace(returncode=0,stdout=out,stderr="")
    with patch("magi_runner.executors.nuclei._find_nuclei",return_value="nuclei.exe"), patch("magi_runner.executors.nuclei.subprocess.run",return_value=cp):
        r=NucleiExecutor().run(job(tmp_path),str(tmp_path),30)
    assert r.status=="success"
    assert r.metadata["finding"]["status"]=="detected"
    assert r.metadata["evidence"]["match_count"]==1

def test_nuclei_no_match_not_detected(tmp_path):
    cp=SimpleNamespace(returncode=0,stdout="",stderr="")
    with patch("magi_runner.executors.nuclei._find_nuclei",return_value="nuclei.exe"), patch("magi_runner.executors.nuclei.subprocess.run",return_value=cp):
        r=NucleiExecutor().run(job(tmp_path),str(tmp_path),30)
    assert r.status=="success"
    assert r.metadata["finding"]["status"]=="not_detected"

def test_nuclei_missing_binary_not_evaluated(tmp_path):
    with patch("magi_runner.executors.nuclei._find_nuclei",return_value=None):
        r=NucleiExecutor().run(job(tmp_path),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["finding"]["status"]=="not_evaluated"
