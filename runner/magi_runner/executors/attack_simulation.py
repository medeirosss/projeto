from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time
import uuid
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


def _http_request(
    host: str,
    port: int,
    timeout: float,
    *,
    tls: bool,
    method: str,
    path: str,
    body: str | None = None,
) -> dict[str, Any]:
    headers = {
        "User-Agent": "MAGI-Attack-Simulator/5.1",
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
            "response_headers": {
                k: v
                for k, v in response.getheaders()
                if k.lower() in {"server", "allow", "www-authenticate", "location", "content-type"}
            },
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
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
        '<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'
    )
    result = _http_request(host, port, timeout, tls=tls, method="POST", path="/wsman", body=body)
    result["winrm_surface"] = bool(result.get("connected") and result.get("status_code") in {200, 401, 403, 405})
    return result


def _in_allowed_scope(host: str, scope: dict[str, Any]) -> bool:
    allowed_hosts = {str(x).strip().lower() for x in (scope.get("allowed_hosts") or []) if str(x).strip()}
    if host.strip().lower() in allowed_hosts:
        return True
    try:
        resolved = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        return False
    for value in scope.get("allowed_networks") or []:
        try:
            if resolved in ipaddress.ip_network(str(value).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _winrm_lateral_path(
    host_a: str,
    host_b: str,
    credential: dict[str, Any],
    scope: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "path": [host_a, host_b],
        "hop_count": 1,
        "host_a": host_a,
        "host_b": host_b,
        "origin_proof": "Host B command is invoked inside the remote Host A session.",
        "scope": scope,
    }
    if not host_b:
        evidence.update({"completed": False, "stop_reason": "secondary_target_missing", "error": "Host B obrigatório."})
        return evidence
    if host_a.strip().lower() == host_b.strip().lower():
        evidence.update({"completed": False, "stop_reason": "duplicate_host", "error": "Host B deve ser diferente do Host A."})
        return evidence
    requested_hops = int(scope.get("max_hops") or 1)
    evidence["scope"]["max_hops"] = max(1, min(5, requested_hops))
    evidence["scope"]["hard_max_hops"] = 5
    if not _in_allowed_scope(host_a, scope) or not _in_allowed_scope(host_b, scope):
        evidence.update({"completed": False, "stop_reason": "scope_violation", "error": "Host fora do Attack Scope autorizado."})
        return evidence
    if int(scope.get("max_hops") or 0) < 1:
        evidence.update({"completed": False, "stop_reason": "max_hops_reached", "error": "Scope não permite o primeiro salto."})
        return evidence

    user = str(credential.get("username") or "").strip()
    domain = str(credential.get("domain") or "").strip()
    secret = str(credential.get("secret") or "")
    if not user or not secret:
        evidence.update({
            "completed": False,
            "stop_reason": "credential_missing",
            "error": "Credential Profile sem usuário ou segredo transitório.",
        })
        return evidence

    identity = f"{domain}\\{user}" if domain and "\\" not in user and "@" not in user else user
    token = uuid.uuid4().hex[:12]
    artifact = f"C:\\MAGI\\magi-was-here-{token}.txt"
    evidence["artifact_path"] = artifact
    evidence["credential_name"] = credential.get("name")
    evidence["credential_id"] = credential.get("id")

    env = os.environ.copy()
    env.update({
        "MAGI_HOST_A": host_a,
        "MAGI_HOST_B": host_b,
        "MAGI_USER": identity,
        "MAGI_SECRET": secret,
        "MAGI_TOKEN": token,
        "MAGI_ARTIFACT": artifact,
    })

    script = r'''
$ErrorActionPreference='Stop'
$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force
$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s)
$artifact=$env:MAGI_ARTIFACT
$token=$env:MAGI_TOKEN
$trustedPath='WSMan:\localhost\Client\TrustedHosts'
$trustedOriginal=$null
$trustedChanged=$false
$transport='winrm_http_negotiate'
try {
  $trustedOriginal=(Get-Item $trustedPath -ErrorAction Stop).Value
  $items=@()
  if($trustedOriginal){$items=@($trustedOriginal -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})}
  if(-not ($items -contains $env:MAGI_HOST_A)){
    $newItems=@($items + $env:MAGI_HOST_A | Select-Object -Unique)
    Set-Item $trustedPath -Value ($newItems -join ',') -Force -ErrorAction Stop
    $trustedChanged=$true
  }
  $resultA=Invoke-Command -ComputerName $env:MAGI_HOST_A -Authentication Negotiate -Credential $c -ArgumentList $artifact,$token -ScriptBlock {
   param($artifact,$token)
   $dir=Split-Path $artifact -Parent
   New-Item -ItemType Directory -Path $dir -Force | Out-Null
   Set-Content -Path $artifact -Value ("MAGI Attack Simulator 5.1.1 evidence " + $token) -Encoding ASCII
   $verified=Test-Path $artifact
   $content=if($verified){Get-Content $artifact -Raw}else{''}
   Remove-Item $artifact -Force -ErrorAction SilentlyContinue
   $cleaned=-not (Test-Path $artifact)
   [pscustomobject]@{hostname=$env:COMPUTERNAME;artifact_created=$verified;artifact_verified=($content -like "*${token}*");cleanup_success=$cleaned}
  }
  $resultB=Invoke-Command -ComputerName $env:MAGI_HOST_A -Authentication Negotiate -Credential $c -ArgumentList $env:MAGI_HOST_B,$env:MAGI_USER,$env:MAGI_SECRET,$artifact,$token -ScriptBlock {
   param($hostB,$user,$secret,$artifact,$token)
   $s2=ConvertTo-SecureString $secret -AsPlainText -Force
   $c2=New-Object System.Management.Automation.PSCredential($user,$s2)
   Invoke-Command -ComputerName $hostB -Authentication Negotiate -Credential $c2 -ArgumentList $artifact,$token -ScriptBlock {
    param($artifact,$token)
    $dir=Split-Path $artifact -Parent
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Set-Content -Path $artifact -Value ("MAGI Attack Simulator 5.1.1 lateral evidence " + $token) -Encoding ASCII
    $verified=Test-Path $artifact
    $content=if($verified){Get-Content $artifact -Raw}else{''}
    Remove-Item $artifact -Force -ErrorAction SilentlyContinue
    $cleaned=-not (Test-Path $artifact)
    [pscustomobject]@{hostname=$env:COMPUTERNAME;artifact_created=$verified;artifact_verified=($content -like "*${token}*");cleanup_success=$cleaned}
   }
  }
  [pscustomobject]@{host_a=$resultA;host_b=$resultB;path=($env:MAGI_HOST_A+" -> "+$env:MAGI_HOST_B);transport=$transport;trustedhosts_temporary=$trustedChanged} | ConvertTo-Json -Depth 6 -Compress
}
finally {
  if($trustedChanged){ try { Set-Item $trustedPath -Value $trustedOriginal -Force -ErrorAction Stop } catch {} }
}
'''

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=max(20, timeout),
            env=env,
            shell=False,
        )
        evidence["powershell_exit_code"] = proc.returncode
        if proc.returncode == 0 and (proc.stdout or "").strip():
            raw = (proc.stdout or "").strip()
            try:
                parsed = json.loads(raw.splitlines()[-1])
            except Exception:
                parsed = {"raw_preview": raw[-1200:]}
            evidence["remote_evidence"] = parsed
            a = parsed.get("host_a") or {}
            b = parsed.get("host_b") or {}
            completed = bool(
                a.get("artifact_verified")
                and a.get("cleanup_success")
                and b.get("artifact_verified")
                and b.get("cleanup_success")
            )
            evidence.update({
                "completed": completed,
                "authentication_success": True,
                "host_a_execution": bool(a.get("artifact_verified")),
                "host_b_execution": bool(b.get("artifact_verified")),
                "cleanup_success": bool(a.get("cleanup_success") and b.get("cleanup_success")),
                "stop_reason": "objective_reached" if completed else "evidence_not_confirmed",
            })
        else:
            err = (proc.stderr or proc.stdout or f"PowerShell exit {proc.returncode}").strip()[-1800:]
            evidence.update({
                "completed": False,
                "authentication_success": False,
                "stop_reason": "authentication_or_transport_failed",
                "error": err,
            })
    except subprocess.TimeoutExpired:
        evidence.update({"completed": False, "stop_reason": "job_timeout", "error": "Tempo limite atingido durante validação WinRM lateral."})
    except FileNotFoundError:
        evidence.update({"completed": False, "stop_reason": "runner_dependency_error", "error": "powershell.exe não encontrado no Runner."})
    return evidence


class AttackSimulationExecutor:
    """MAGI Attack Simulator 5.1.1.

    Protocol tests prove only exposure/preconditions. The authenticated 5.1 path
    can prove one authorized WinRM lateral hop with a benign artifact + cleanup.
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
        if sim_type != "winrm_lateral_path" and not port:
            return self._finish(started_at, started, "failed", 2, "", "Porta da simulação é obrigatória.", target, sim_type, {}, False, "invalid_simulation")

        scenario = str(payload.get("scenario_name") or payload.get("task_key") or sim_type)

        if sim_type == "winrm_lateral_path":
            host_b = str(payload.get("host_b") or "").strip()
            evidence = _winrm_lateral_path(target, host_b, payload.get("credential") or {}, payload.get("scope") or {}, timeout_seconds)
            confirmed = bool(evidence.get("completed"))
            attack_result = "lateral_movement_confirmed" if confirmed else "lateral_movement_not_confirmed"
            message = (
                f"Movimento lateral benigno confirmado: {target} → {host_b}."
                if confirmed
                else f"Simulação executada, mas o movimento lateral {target} → {host_b} não foi confirmado ({evidence.get('stop_reason')})."
            )
            metadata = {
                "engine": "magi_attack_simulator",
                "engine_version": "5.1.1",
                "scenario": scenario,
                "category": payload.get("attack_category"),
                "simulation_type": sim_type,
                "safe_mode": True,
                "destructive": False,
                "executed_real_test": True,
                "execution_scope": "lateral_path_remote",
                "requested_target": target,
                "secondary_target": host_b,
                "execution_status": "success",
                "attack_result": attack_result,
                "payload_status": "executed" if confirmed else "not_confirmed",
                "authentication_status": "success" if evidence.get("authentication_success") else "not_confirmed",
                "lateral_movement_status": "confirmed" if confirmed else "not_confirmed",
                "detection_status": "not_evaluated",
                "confirmation_status": attack_result,
                "finding": {"status": attack_result, "detected": confirmed, "message": message},
                "evidence": evidence,
            }
            stdout = json.dumps(
                {"scenario": scenario, "path": [target, host_b], "attack_result": attack_result, "evidence": evidence},
                ensure_ascii=False,
                indent=2,
            )
            return self._finish(started_at, started, "success", 0, stdout, "", target, sim_type, metadata, True, attack_result, preserve_metadata=True)

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
            method = "OPTIONS" if sim_type == "http_options" else "POST" if sim_type == "http_canary_post" else "GET"
            body = json.dumps({"magi_simulation": True, "version": "5.1", "destructive": False}) if sim_type == "http_canary_post" else None
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

        attack_result = "precondition_confirmed" if observed else "precondition_not_confirmed"
        message = (
            f"Pré-condição confirmada: {scenario}. Serviço/protocolo acessível; autenticação e payload não foram executados."
            if observed
            else f"Pré-condição não confirmada: {scenario}. Serviço/protocolo não respondeu ao teste."
        )
        finding = {"status": attack_result, "detected": observed, "message": message}
        metadata = {
            "engine": "magi_attack_simulator",
            "engine_version": "5.1.1",
            "scenario": scenario,
            "category": payload.get("attack_category"),
            "simulation_type": sim_type,
            "safe_mode": True,
            "destructive": False,
            "executed_real_test": True,
            "execution_scope": "target_remote",
            "requested_target": target,
            "execution_status": "success",
            "attack_result": attack_result,
            "payload_status": "not_executed",
            "authentication_status": "not_attempted",
            "lateral_movement_status": "not_confirmed",
            "detection_status": "not_evaluated",
            "confirmation_status": attack_result,
            "finding": finding,
            "evidence": evidence,
        }
        stdout = json.dumps({"scenario": scenario, "target": target, "attack_result": attack_result, "evidence": evidence}, ensure_ascii=False, indent=2)
        return self._finish(started_at, started, "success", 0, stdout, "", target, sim_type, metadata, True, attack_result, preserve_metadata=True)

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
                "engine_version": "5.1.1",
                "simulation_type": sim_type,
                "safe_mode": True,
                "destructive": False,
                "executed_real_test": executed,
                "execution_scope": "target_remote",
                "requested_target": target,
                "execution_status": status,
                "attack_result": "not_evaluated",
                "payload_status": "not_executed",
                "authentication_status": "not_attempted",
                "lateral_movement_status": "not_confirmed",
                "detection_status": "not_evaluated",
                "confirmation_status": confirmation,
                "evidence": metadata,
                "finding": {
                    "status": "error" if status in {"failed", "error"} else "not_evaluated",
                    "detected": False,
                    "message": stderr or confirmation,
                },
            }
        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            metadata=metadata,
        )
