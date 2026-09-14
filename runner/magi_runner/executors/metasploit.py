from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .base import ExecutionResult
from magi_runner.core.metasploit_capability import find_msfconsole

TECHNIQUES = {
    "MAGI-M-ATK-END-001": {
        "module": "auxiliary/scanner/smb/smb_version",
        "category": "Endpoint",
        "credential_required": False,
    },
    "MAGI-M-ATK-AD-001": {
        "module": "auxiliary/scanner/kerberos/kerberos_login",
        "category": "Active Directory",
        "credential_required": True,
    },
    "MAGI-M-ATK-APP-001": {
        "module": "auxiliary/scanner/http/options",
        "category": "Application",
        "credential_required": False,
    },
    "MAGI-M-ATK-NET-001": {
        "module": "auxiliary/scanner/snmp/snmp_enum",
        "category": "Network Node",
        "credential_required": True,
    },
}

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9_.:\-\[\]]+$")

def _safe_console_value(value: Any, field: str) -> str:
    s = str(value or "").strip()
    if any(x in s for x in ("\r", "\n", ";")):
        raise ValueError(f"{field} contém caracteres não permitidos para execução Metasploit.")
    return s

def _target(value: Any) -> str:
    s = _safe_console_value(value, "target")
    if not s or not _SAFE_TARGET.fullmatch(s):
        raise ValueError("Target inválido para execução Metasploit.")
    return s


def _application_url(value: Any) -> dict[str, Any]:
    raw = _safe_console_value(value, "URL")
    if not raw:
        raise ValueError("URL da aplicação é obrigatória.")
    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        raise ValueError("URL da aplicação inválida.") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL da aplicação deve utilizar http:// ou https://.")
    if not parsed.hostname:
        raise ValueError("URL da aplicação não possui host válido.")
    if parsed.username or parsed.password:
        raise ValueError("Credenciais embutidas na URL não são permitidas.")
    if parsed.fragment:
        raise ValueError("Fragmentos (#...) não são usados em ataques HTTP e devem ser removidos.")

    host = _target(parsed.hostname)
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Porta inválida na URL da aplicação.") from exc
    if port < 1 or port > 65535:
        raise ValueError("Porta inválida na URL da aplicação.")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    path = _safe_console_value(path, "TARGETURI")
    if not path.startswith("/"):
        path = "/" + path

    return {
        "url": raw,
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "path": path,
        "ssl": scheme == "https",
    }


def _resolve_application_host(host: str, port: int) -> dict[str, Any]:
    """Resolve Application host in the Runner before invoking Metasploit.

    Metasploit/Ruby on Windows can fail name resolution even when the Windows
    host resolver succeeds.  MAGI therefore resolves the hostname itself,
    passes the IPv4 address as RHOSTS, and preserves the original hostname as
    VHOST so HTTP virtual hosting continues to work.
    """
    try:
        ip_obj = ipaddress.ip_address(host)
        return {
            "hostname": host,
            "resolved_ip": str(ip_obj),
            "dns_resolution": "not_required",
            "vhost_required": False,
        }
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS_RESOLUTION_FAILED: não foi possível resolver {host} no Runner: {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise RuntimeError(f"DNS_RESOLUTION_FAILED: nenhuma resposta IPv4 para {host} no Runner.")

    return {
        "hostname": host,
        "resolved_ip": addresses[0],
        "resolved_addresses": addresses,
        "dns_resolution": "runner",
        "vhost_required": True,
    }

def _extract(stdout: str, task_key: str, target: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {"target": target}
    if task_key == "MAGI-M-ATK-END-001":
        m = re.search(r"SMB Detected \(versions:\s*([^)]+)\)", stdout, re.I)
        if m: evidence["smb_versions"] = [x.strip() for x in m.group(1).split(",")]
        m = re.search(r"preferred dialect:\s*([^)]+?)(?:\)|, compression)", stdout, re.I)
        if m: evidence["preferred_dialect"] = m.group(1).strip()
        m = re.search(r"signatures:\s*([^) ,]+)", stdout, re.I)
        if m: evidence["signing"] = m.group(1).strip()
        m = re.search(r"encryption capabilities:\s*([^)]+)", stdout, re.I)
        if m: evidence["encryption"] = m.group(1).strip()
        m = re.search(r"Host is running Version\s+([0-9.]+)\s+\(likely\s+([^)]+)\)", stdout, re.I)
        if m:
            evidence["os_build"] = m.group(1)
            evidence["os_guess"] = m.group(2)
        m = re.search(r"authentication domain:\s*([^)]+)", stdout, re.I)
        if m: evidence["authentication_domain"] = m.group(1).strip()
    elif task_key == "MAGI-M-ATK-APP-001":
        methods = sorted(set(re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT)\b", stdout, re.I)))
        if methods: evidence["http_methods"] = [x.upper() for x in methods]
    elif task_key == "MAGI-M-ATK-NET-001":
        for label in ("sysName", "sysDescr", "sysContact", "sysLocation"):
            m = re.search(rf"{label}(?:\.0)?\s*[:=]\s*(.+)", stdout, re.I)
            if m: evidence[label] = m.group(1).strip()
    elif task_key == "MAGI-M-ATK-AD-001":
        low = stdout.lower()
        evidence["authentication_confirmed"] = any(x in low for x in (
            "successful login", "valid credential", "success:", "login successful", "user found:"
        ))
        evidence["account_status_signal"] = next((x for x in (
            "locked out", "disabled", "pre-authentication", "preauthentication"
        ) if x in low), None)
    return evidence

def _normalized_status(task_key: str, stdout: str, stderr: str, returncode: int, evidence: dict[str, Any]) -> tuple[str, str]:
    blob = (stdout + "\n" + stderr).lower()
    fatal = ("unknown command", "failed to load module", "invalid option", "missing required option")
    if returncode not in (0, None) or any(x in blob for x in fatal):
        return "failed", "FAILED"
    if task_key == "MAGI-M-ATK-AD-001":
        if evidence.get("authentication_confirmed"):
            return "success", "SUCCESS"
        # For credential validation, module completion alone is NOT a positive result.
        if any(x in blob for x in ("incorrect", "invalid credential", "login failed", "authentication failed", "user not found")):
            return "success", "AUTHENTICATION_FAILED"
        if "module execution completed" in blob or returncode == 0:
            return "success", "AUTHENTICATION_FAILED"
    # Scanner/enum modules completed successfully; findings are preserved in evidence.
    if "module execution completed" in blob or "scanned 1 of 1" in blob or returncode == 0:
        return "success", "SUCCESS"
    return "failed", "FAILED"


def _cleanup_kerberos_loot(stdout: str) -> dict[str, Any]:
    matches = re.findall(r"ticket saved to\s+(.+?)(?:\r?$)", stdout or "", re.I | re.M)
    if not matches:
        return {"required": False, "attempted": False, "success": True, "artifacts": []}
    artifacts = []
    overall = True
    for raw in matches:
        path = raw.strip().strip('"')
        item = {"path": path, "deleted": False}
        try:
            artifact = Path(path)
            if artifact.exists() and artifact.is_file():
                artifact.unlink()
            item["deleted"] = not artifact.exists()
        except Exception as exc:
            overall = False
            item["error"] = str(exc)
        artifacts.append(item)
    return {
        "required": True,
        "attempted": True,
        "success": overall and all(x.get("deleted") for x in artifacts),
        "artifacts": artifacts,
    }

class MetasploitExecutor:
    name = "metasploit"

    def run(self, job: dict[str, Any], job_dir: str, timeout: int) -> ExecutionResult:
        started_dt = datetime.now(timezone.utc)
        started = started_dt.isoformat()
        payload = job.get("payload") or {}
        key = str(payload.get("task_key") or "")
        spec = TECHNIQUES.get(key)
        if not spec:
            raise ValueError("Técnica Metasploit não pertence à allowlist MAGI 5.5.0.")

        raw_target = payload.get("target") or job.get("target")
        application = _application_url(raw_target) if key == "MAGI-M-ATK-APP-001" else None
        application_resolution = (
            _resolve_application_host(application["host"], application["port"])
            if application else None
        )
        target = application_resolution["resolved_ip"] if application_resolution else _target(raw_target)
        detection = payload.get("detection") or {}
        credential = payload.get("credential") or {}
        if spec["credential_required"] and not credential.get("secret"):
            raise ValueError("Credential Profile é obrigatório para esta técnica.")

        msf = find_msfconsole(payload.get("metasploit_path"))
        if not msf:
            raise RuntimeError("Metasploit indisponível neste Runner: msfconsole não encontrado.")

        commands = [f"use {spec['module']}", f"set RHOSTS {target}"]
        if key == "MAGI-M-ATK-AD-001":
            username = _safe_console_value(credential.get("username"), "username")
            password = _safe_console_value(credential.get("secret"), "password")
            domain = _safe_console_value(credential.get("domain"), "domain")
            if not username or not password:
                raise ValueError("Usuário e senha são obrigatórios para Kerberos Authentication Validation.")
            commands += [f"set USERNAME {username}", f"set PASSWORD {password}", "set STOP_ON_SUCCESS true"]
            if domain:
                commands.append(f"set DOMAIN {domain}")
        elif key == "MAGI-M-ATK-APP-001":
            # Application attacks accept a full URL. The Runner resolves DNS
            # itself and gives Metasploit an IP in RHOSTS.  VHOST preserves the
            # original hostname for S3/static hosting, reverse proxies and other
            # name-based virtual hosts.
            port = int(application["port"])
            uri = application["path"]
            commands += [f"set RPORT {port}", f"set TARGETURI {uri}"]
            if application_resolution.get("vhost_required"):
                commands.append(f"set VHOST {application['host']}")
            if application["ssl"]:
                commands.append("set SSL true")
        elif key == "MAGI-M-ATK-NET-001":
            community = _safe_console_value(credential.get("secret"), "COMMUNITY")
            if not community:
                raise ValueError("SNMP Credential Profile/community é obrigatório para SNMP Enumeration.")
            commands += ["set RPORT 161", f"set COMMUNITY {community}"]

        commands += ["run", "exit"]
        rc = "; ".join(commands)
        proc = subprocess.run(
            [msf, "-q", "-x", rc],
            capture_output=True, text=True, timeout=max(20, int(timeout)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        cleanup = _cleanup_kerberos_loot(stdout) if key == "MAGI-M-ATK-AD-001" else {"required": False, "attempted": False, "success": True, "artifacts": []}
        evidence = _extract(stdout, key, target)
        if key == "MAGI-M-ATK-APP-001" and application:
            evidence.update({
                "application_url": application["url"],
                "hostname": application["host"],
                "resolved_target": application_resolution["resolved_ip"],
                "resolved_ip": application_resolution["resolved_ip"],
                "resolved_addresses": application_resolution.get("resolved_addresses", [application_resolution["resolved_ip"]]),
                "dns_resolution": application_resolution["dns_resolution"],
                "vhost": application["host"] if application_resolution.get("vhost_required") else None,
                "port": application["port"],
                "protocol": application["scheme"].upper(),
                "path": application["path"],
                "ssl": application["ssl"],
            })
        if key == "MAGI-M-ATK-AD-001":
            evidence["credential_material_produced"] = bool(cleanup.get("required"))
            evidence["runner_cleanup"] = {
                "required": bool(cleanup.get("required")),
                "attempted": bool(cleanup.get("attempted")),
                "success": bool(cleanup.get("success")),
            }
        status, attack_result = _normalized_status(key, stdout, stderr, proc.returncode, evidence)
        finished_dt = datetime.now(timezone.utc)
        finished = finished_dt.isoformat()
        metadata = {
            "executed_real_test": True,
            "execution_scope": "target_remote",
            "requested_target": application["url"] if application else target,
            "provider": "metasploit",
            "provider_path": msf,
            "module": spec["module"],
            "technique_id": key,
            "attack_result": attack_result,
            "confirmation_status": "confirmed" if attack_result == "SUCCESS" else attack_result.lower(),
            "finding": {
                "status": attack_result.lower(),
                "detected": attack_result == "SUCCESS",
                "message": (
                    "Autenticação Kerberos confirmada via Metasploit."
                    if key == "MAGI-M-ATK-AD-001" and attack_result == "SUCCESS"
                    else "Credencial Kerberos não confirmada."
                    if key == "MAGI-M-ATK-AD-001"
                    else f"{key} concluída via Metasploit."
                ),
            },
            "runner_cleanup": {
                "required": bool(cleanup.get("required")),
                "attempted": bool(cleanup.get("attempted")),
                "success": bool(cleanup.get("success")),
            },
            "normalized_evidence": evidence,
            "warning_present": "warning:" in (stdout + stderr).lower(),
        }
        duration = (finished_dt - started_dt).total_seconds()
        return ExecutionResult(
            status=status, exit_code=proc.returncode, stdout=stdout, stderr=stderr,
            started_at=started, finished_at=finished, duration_seconds=duration, metadata=metadata
        )
