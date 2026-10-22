from pathlib import Path
from unittest.mock import patch

from magi_runner.executors.security_check import SecurityCheckExecutor


def job(target="192.168.0.100", port=445):
    return {
        "target": target,
        "payload": {
            "target": target,
            "task_key": "MAGI-NET-002",
            "repository_key": "magi",
            "detection": {"type": "tcp_port", "port": port, "finding_when": "open"},
            "remediation": "test",
        },
    }


def test_unreachable_is_not_evaluated(tmp_path):
    preflight = {
        "status": "unreachable",
        "reachable": False,
        "target": "192.168.0.97",
        "resolved_ip": "192.168.0.97",
        "confidence": "medium",
        "reason": "no_reachability_evidence",
        "signals": [],
    }
    with patch("magi_runner.executors.security_check._reachability_preflight", return_value=preflight):
        result = SecurityCheckExecutor().run(job("192.168.0.97"), str(tmp_path), 30)
    assert result.status == "target_unreachable"
    assert result.metadata["finding"]["status"] == "not_evaluated"
    assert result.metadata["confirmation_status"] == "target_unreachable"


def test_reachable_open_is_detected(tmp_path):
    preflight = {
        "status": "reachable",
        "reachable": True,
        "target": "192.168.0.100",
        "resolved_ip": "192.168.0.100",
        "confidence": "high",
        "reason": "tcp_open:445",
        "signals": [],
        "check_probe": {"state": "open", "reachable": True, "latency_ms": 10.0, "error": None},
    }
    with patch("magi_runner.executors.security_check._reachability_preflight", return_value=preflight):
        result = SecurityCheckExecutor().run(job(), str(tmp_path), 30)
    assert result.status == "success"
    assert result.metadata["finding"]["status"] == "detected"
    assert result.metadata["evidence"]["reachability"]["status"] == "reachable"


def test_reachable_filtered_is_not_detected(tmp_path):
    preflight = {
        "status": "reachable",
        "reachable": True,
        "target": "192.168.0.100",
        "resolved_ip": "192.168.0.100",
        "confidence": "high",
        "reason": "icmp_reply",
        "signals": [],
        "check_probe": {"state": "filtered_or_unreachable", "reachable": False, "latency_ms": 1000.0, "error": "timed out"},
    }
    final_probe = {"state": "filtered_or_unreachable", "reachable": False, "latency_ms": 1000.0, "error": "timed out"}
    with patch("magi_runner.executors.security_check._reachability_preflight", return_value=preflight), \
         patch("magi_runner.executors.security_check._tcp_probe", return_value=final_probe):
        result = SecurityCheckExecutor().run(job(), str(tmp_path), 30)
    assert result.status == "success"
    assert result.metadata["finding"]["status"] == "not_detected"
    assert result.metadata["evidence"]["state"] == "closed_or_filtered"
