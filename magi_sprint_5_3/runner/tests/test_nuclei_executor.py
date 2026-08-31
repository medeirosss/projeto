from types import SimpleNamespace
from unittest.mock import patch
from magi_runner.executors.nuclei import NucleiExecutor

def _cap(tmp_path, template_exists=True):
    exe=tmp_path/"nuclei.exe"; exe.write_text("x")
    templates=tmp_path/"templates"
    if template_exists:
        (templates/"http").mkdir(parents=True,exist_ok=True)
        (templates/"http"/"test.yaml").write_text("id: test")
    return {
        "binary_path":str(exe),
        "templates_path":str(templates),
        "runtime_policy":"fixed_bundled",
        "runtime_integrity":{"status":"ok"},
        "searched_paths":[str(exe)],
    }

def job():
    return {"target":"192.168.0.100","payload":{
        "target":"192.168.0.100","template":"http/test.yaml","executor":"nuclei",
        "profile_name":"HTTP Test","protocol":"http","ports":[80]
    }}

def _open_probe(*args,**kwargs):
    return {"method":"tcp","port":80,"state":"open","reachable":True,"latency_ms":1.0,"error":None}

def test_nuclei_match_detected(tmp_path):
    out='{"template-id":"CVE-2026-12345","matched-at":"http://192.168.0.100","info":{"name":"Test CVE","severity":"high"}}\n'
    cp=SimpleNamespace(returncode=0,stdout=out,stderr="")
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=_cap(tmp_path)), \
         patch("magi_runner.executors.nuclei._tcp_probe",side_effect=_open_probe), \
         patch("magi_runner.executors.nuclei.subprocess.run",return_value=cp):
        r=NucleiExecutor().run(job(),str(tmp_path),30)
    assert r.status=="success"
    assert r.metadata["finding"]["status"]=="detected"
    assert r.metadata["evidence"]["match_count"]==1
    assert r.metadata["evidence"]["confirmed_cves"]==["CVE-2026-12345"]

def test_nuclei_no_match_not_detected(tmp_path):
    cp=SimpleNamespace(returncode=0,stdout="",stderr="")
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=_cap(tmp_path)), \
         patch("magi_runner.executors.nuclei._tcp_probe",side_effect=_open_probe), \
         patch("magi_runner.executors.nuclei.subprocess.run",return_value=cp):
        r=NucleiExecutor().run(job(),str(tmp_path),30)
    assert r.status=="success"
    assert r.metadata["finding"]["status"]=="not_detected"
    assert r.metadata["executed_real_test"] is True

def test_nuclei_missing_binary_not_evaluated(tmp_path):
    cap=_cap(tmp_path); cap["binary_path"]=None; cap["searched_paths"]=["missing.exe"]
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=cap):
        r=NucleiExecutor().run(job(),str(tmp_path),30)
    assert r.status=="failed"
    assert r.metadata["finding"]["status"]=="not_evaluated"
    assert r.metadata["executed_real_test"] is False
    assert r.metadata["evidence"]["reason"]=="engine_unavailable"
