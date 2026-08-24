from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from .base import ExecutionResult


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _target(job: dict[str, Any]) -> str:
    return str(job.get("target") or (job.get("payload") or {}).get("target") or "").strip()


def _tcp_connect(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            peer = sock.getpeername()
        return {
            "connected": True,
            "port": port,
            "peer": f"{peer[0]}:{peer[1]}",
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
        }
    except OSError as exc:
        return {
            "connected": False,
            "port": port,
            "error": str(exc),
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
        }


def _banner(host: str, port: int, timeout: float) -> dict[str, Any]:
    result = _tcp_connect(host, port, timeout)
    if not result.get("connected"):
        return result
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = sock.recv(512)
        result["banner"] = raw.decode("utf-8", errors="replace").strip()[:300]
    except OSError as exc:
        result["banner_error"] = str(exc)
    return result


def _rdp_negotiate(host: str, port: int, timeout: float) -> dict[str, Any]:
    # Minimal X.224 connection request used only to confirm that an RDP stack responds.
    packet = bytes.fromhex("030000130ee000000000000100080003000000")
    result = _tcp_connect(host, port, timeout)
    if not result.get("connected"):
        return result
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            response = sock.recv(128)
        result["protocol_response"] = response.hex()[:256]
        result["rdp_response"] = bool(response)
    except OSError as exc:
        result["protocol_error"] = str(exc)
        result["rdp_response"] = False
    return result


def _http_request(host: str, port: int, timeout: float, *, tls: bool, method: str, path: str, body: str | None = None) -> dict[str, Any]:
    headers = {
        "User-Agent": "MAGI-Attack-Simulator/5.0",
        "X-MAGI-Simulation": "benign-control-validation",
        "X-MAGI-Destructive": "false",
        "Connection": "close",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    context = None
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    conn_cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    conn = conn_cls(host, port=port, timeout=timeout, context=context) if tls else conn_cls(host, port=port, timeout=timeout)
    started = time.monotonic()
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(1024)
        return {
            "connected": True,
            "port": port,
            "tls": tls,
            "method": method,
            "path": path,
            "status_code": response.status,
            "reason": response.reason,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "response_headers": {k: v for k, v in response.getheaders() if k.lower() in {"server", "allow", "www-authenticate", "location", "content-type"}},
            "response_preview": raw.decode("utf-8", errors="replace")[:300],
        }
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return {
            "connected": False,
            "port": port,
            "tls": tls,
            "method": method,
            "path": path,
            "error": str(exc),
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
        }
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _winrm_identify(host: str, port: int, timeout: float, *, tls: bool) -> dict[str, Any]:
    # WS-Management Identify request. It does not authenticate or execute a command.
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
        '<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'
    )
    result = _http_request(host, port, timeout, tls=tls, method="POST", path="/wsman", body=body)
    result["winrm_surface"] = bool(result.get("connected") and result.get("status_code") in {200, 401, 403, 405})
    return result


class AttackSimulationExecutor:
    """Non-destructive Attack Simulation engine for MAGI 5.0.

    The executor intentionally limits itself to protocol negotiation, harmless
    telemetry requests and management-plane reachability. It does not exploit
    vulnerabilities, brute-force credentials, execute remote commands, persist,
    dump credentials, or alter target state.
    """

    name = "attack_simulation"

    def run(self, job: dict[str, Any], workdir: str, timeout_seconds: int) -> ExecutionResult:
        started_at = _now()
        started = time.monotonic()
        payload = job.get("payload") or {}
        target = _target(job)
        simulation = payload.get("simulation") or payload.get("detection") or {}
        sim_type = str(simulation.get("type") or "tcp_control_plane").lower()
        port = int(simulation.get("port") or 0)
        probe_timeout = max(0.5, min(float(simulation.get("probe_timeout_seconds") or 3.0), float(timeout_seconds)))

        if not target:
            return self._finish(started_at, started, "failed", 2, "", "Target obrigatório.", target, sim_type, {}, False, "invalid_target")
        if not port:
            return self._finish(started_at, started, "failed", 2, "", "Porta da simulação é obrigatória.", target, sim_type, {}, False, "invalid_simulation")

        try:
            socket.getaddrinfo(target, port)
        except OSError as exc:
            return self._finish(started_at, started, "target_unreachable", 3, "", str(exc), target, sim_type, {"dns_error": str(exc)}, False, "target_unreachable")

        if sim_type == "tcp_control_plane":
            evidence = _tcp_connect(target, port, probe_timeout)
        elif sim_type == "protocol_banner":
            evidence = _banner(target, port, probe_timeout)
        elif sim_type == "rdp_negotiation":
            evidence = _rdp_negotiate(target, port, probe_timeout)
        elif sim_type == "winrm_identify":
            evidence = _winrm_identify(target, port, probe_timeout, tls=bool(simulation.get("tls")))
        elif sim_type in {"http_canary", "http_options", "http_canary_post"}:
            method = "GET"
            body = None
            if sim_type == "http_options":
                method = "OPTIONS"
            elif sim_type == "http_canary_post":
                method = "POST"
                body = json.dumps({"magi_simulation": True, "version": "5.0", "destructive": False})
            evidence = _http_request(
                target,
                port,
                probe_timeout,
                tls=bool(simulation.get("tls")),
                method=method,
                path=str(simulation.get("path") or "/magi-attack-simulation"),
                body=body,
            )
        else:
            return self._finish(started_at, started, "failed", 2, "", f"Tipo de simulação não suportado: {sim_type}", target, sim_type, {}, False, "unsupported_simulation")

        observed = bool(evidence.get("connected"))
        if sim_type == "rdp_negotiation":
            observed = bool(evidence.get("rdp_response"))
        elif sim_type == "winrm_identify":
            observed = bool(evidence.get("winrm_surface"))

        scenario = str(payload.get("scenario_name") or payload.get("task_key") or sim_type)
        message = (
            f"Controle alcançado durante simulação benigna: {scenario}." if observed
            else f"Controle não alcançado durante simulação benigna: {scenario}."
        )
        finding = {
            "status": "detected" if observed else "not_detected",
            "detected": observed,
            "message": message,
        }
        metadata = {
            "engine": "magi_attack_simulator",
            "engine_version": "5.0",
            "scenario": scenario,
            "category": payload.get("attack_category"),
            "simulation_type": sim_type,
            "safe_mode": True,
            "destructive": False,
            "executed_real_test": True,
            "execution_scope": "target_remote",
            "requested_target": target,
            "confirmation_status": "control_reachable" if observed else "control_not_reachable",
            "finding": finding,
            "evidence": evidence,
        }
        stdout = json.dumps({"scenario": scenario, "target": target, "finding": finding, "evidence": evidence}, ensure_ascii=False, indent=2)
        return self._finish(started_at, started, "success", 0, stdout, "", target, sim_type, metadata, True, metadata["confirmation_status"], preserve_metadata=True)

    def _finish(
        self,
        started_at: str,
        started: float,
        status: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        target: str,
        sim_type: str,
        metadata: dict[str, Any],
        executed: bool,
        confirmation: str,
        preserve_metadata: bool = False,
    ) -> ExecutionResult:
        if not preserve_metadata:
            metadata = {
                "engine": "magi_attack_simulator",
                "engine_version": "5.0",
                "simulation_type": sim_type,
                "safe_mode": True,
                "destructive": False,
                "executed_real_test": executed,
                "execution_scope": "target_remote",
                "requested_target": target,
                "confirmation_status": confirmation,
                "evidence": metadata,
                "finding": {
                    "status": "error" if status in {"failed", "error"} else "not_evaluated",
                    "detected": False,
                    "message": stderr or confirmation,
                },
            }
        finished_at = _now()
        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(time.monotonic() - started, 3),
            metadata=metadata,
        )
