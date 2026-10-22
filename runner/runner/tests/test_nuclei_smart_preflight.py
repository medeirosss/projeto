from unittest.mock import patch
from magi_runner.executors.nuclei import NucleiExecutor

def _cap(tmp_path):
    exe=tmp_path/"nuclei.exe"; exe.write_text("x")
    templates=tmp_path/"templates"; (templates/"http"/"cves").mkdir(parents=True)
    (templates/"http"/"cves"/"test.yaml").write_text("id: test")
    return {"binary_path":str(exe),"templates_path":str(templates),"runtime_policy":"fixed_bundled",
            "runtime_integrity":{"status":"ok"},"searched_paths":[str(exe)]}

def _job():
    return {"target":"192.168.0.100","payload":{"target":"192.168.0.100","template":"http/cves/",
        "profile_name":"CVE HTTP/HTTPS","protocol":"http","ports":[80,443]}}

def test_alive_without_http_is_not_applicable(tmp_path):
    filtered={"state":"filtered_or_unreachable","reachable":False,"port":80}
    reach={"reachable":True,"status":"reachable","reason":"arp_response","signals":[]}
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=_cap(tmp_path)), \
         patch("magi_runner.executors.nuclei._tcp_probe",return_value=filtered), \
         patch("magi_runner.executors.nuclei._reachability_preflight",return_value=reach):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="success"
    assert r.metadata["finding"]["status"]=="not_applicable"
    assert r.metadata["executed_real_test"] is False

def test_unreachable_is_not_evaluated(tmp_path):
    filtered={"state":"filtered_or_unreachable","reachable":False,"port":80}
    reach={"reachable":False,"status":"unreachable","reason":"no_reachability_evidence","signals":[]}
    with patch("magi_runner.executors.nuclei.nuclei_capability",return_value=_cap(tmp_path)), \
         patch("magi_runner.executors.nuclei._tcp_probe",return_value=filtered), \
         patch("magi_runner.executors.nuclei._reachability_preflight",return_value=reach):
        r=NucleiExecutor().run(_job(),str(tmp_path),30)
    assert r.status=="target_unreachable"
    assert r.metadata["finding"]["status"]=="not_evaluated"
    assert r.metadata["executed_real_test"] is False
