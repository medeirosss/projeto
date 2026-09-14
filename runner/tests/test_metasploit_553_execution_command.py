from types import SimpleNamespace
from magi_runner.executors import metasploit as msf


def test_application_execution_uses_resolved_ip_and_vhost(monkeypatch, tmp_path):
    monkeypatch.setattr(msf, "find_msfconsole", lambda explicit=None: r"C:\\metasploit-framework\\bin\\msfconsole.bat")
    monkeypatch.setattr(msf, "_resolve_application_host", lambda host, port: {
        "hostname": host,
        "resolved_ip": "52.216.220.13",
        "resolved_addresses": ["52.216.220.13"],
        "dns_resolution": "runner",
        "vhost_required": True,
    })
    captured = {}
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(
            stdout="[*] Auxiliary module execution completed\n",
            stderr="",
            returncode=0,
        )
    monkeypatch.setattr(msf.subprocess, "run", fake_run)

    job = {"payload": {
        "task_key": "MAGI-M-ATK-APP-001",
        "target": "http://ad360centric.s3-website-us-east-1.amazonaws.com/",
        "detection": {},
    }}
    result = msf.MetasploitExecutor().run(job, str(tmp_path), 30)
    command = captured["argv"][3]
    assert "set RHOSTS 52.216.220.13" in command
    assert "set VHOST ad360centric.s3-website-us-east-1.amazonaws.com" in command
    assert "set RPORT 80" in command
    assert "set TARGETURI /" in command
    assert result.metadata["normalized_evidence"]["resolved_ip"] == "52.216.220.13"
    assert result.metadata["normalized_evidence"]["vhost"] == "ad360centric.s3-website-us-east-1.amazonaws.com"
