from __future__ import annotations

import http.server
import socketserver
import threading

from magi_runner.executors.attack_simulation import AttackSimulationExecutor


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"magi-test")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        return


def _server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv


def test_http_canary_is_non_destructive(tmp_path):
    srv = _server()
    try:
        port = srv.server_address[1]
        job = {
            "job_id": "1",
            "target": "127.0.0.1",
            "payload": {
                "task_key": "MAGI-ATK-APP-TEST",
                "scenario_name": "HTTP canary test",
                "attack_category": "Application",
                "simulation": {"type": "http_canary", "port": port, "path": "/magi-attack-simulation"},
            },
        }
        result = AttackSimulationExecutor().run(job, str(tmp_path), 5)
        assert result.status == "success"
        assert result.metadata["safe_mode"] is True
        assert result.metadata["destructive"] is False
        assert result.metadata["executed_real_test"] is True
        assert result.metadata["finding"]["detected"] is True
        assert result.metadata["attack_result"] == "precondition_confirmed"
        assert result.metadata["payload_status"] == "not_executed"
        assert result.metadata["evidence"]["status_code"] == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_closed_port_returns_not_detected(tmp_path):
    # Reserve and release a local port so it is very likely closed for the probe.
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    job = {
        "job_id": "2",
        "target": "127.0.0.1",
        "payload": {
            "task_key": "MAGI-ATK-END-TEST",
            "scenario_name": "TCP control test",
            "attack_category": "Endpoint",
            "simulation": {"type": "tcp_control_plane", "port": port, "probe_timeout_seconds": 0.5},
        },
    }
    result = AttackSimulationExecutor().run(job, str(tmp_path), 5)
    assert result.status == "success"
    assert result.metadata["finding"]["detected"] is False
    assert result.metadata["confirmation_status"] == "precondition_not_confirmed"


def test_manual_lateral_path_respects_scope_and_requires_credential(tmp_path):
    job = {
        "job_id": "3",
        "target": "192.0.2.10",
        "payload": {
            "task_key": "MAGI-ATK-END-101",
            "scenario_name": "WinRM Lateral Movement Path Validation",
            "attack_category": "Endpoint",
            "host_b": "192.0.2.11",
            "scope": {"allowed_hosts": ["192.0.2.10", "192.0.2.11"], "max_hops": 1, "hard_max_hops": 5},
            "credential": {},
            "simulation": {"type": "winrm_lateral_path", "port": 5985},
        },
    }
    result = AttackSimulationExecutor().run(job, str(tmp_path), 5)
    assert result.status == "success"
    assert result.metadata["attack_result"] == "lateral_movement_not_confirmed"
    assert result.metadata["evidence"]["stop_reason"] == "credential_missing"
    assert result.metadata["lateral_movement_status"] == "not_confirmed"
