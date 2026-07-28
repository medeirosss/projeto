from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import ExecutionResult
from magi_runner.utils.dns_resolver import resolve_ptr

_ALLOWED_REASONS = {"arp-response", "echo-reply", "timestamp-reply", "address-mask-reply", "syn-ack", "reset", "conn-refused", "udp-response", "proto-response"}


def find_nmap(configured_path: str | None = None) -> str | None:
    candidates = [configured_path, shutil.which("nmap.exe"), shutil.which("nmap")]
    if os.name == "nt":
        candidates += [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    return None


def nmap_capability(configured_path: str | None = None) -> dict[str, Any]:
    path = find_nmap(configured_path)
    if not path:
        return {"available": False, "message": "Nmap não encontrado no Runner."}
    version = None
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        first = (proc.stdout or proc.stderr or "").splitlines()[0]
        match = re.search(r"Nmap version\s+([^\s]+)", first, re.I)
        version = match.group(1) if match else first[:80]
    except Exception as exc:
        return {"available": False, "path": path, "message": f"Falha ao validar Nmap: {exc}"}
    return {"available": True, "path": path, "version": version}


def _validate_target(value: str) -> tuple[str, int]:
    value = value.strip()
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError("Somente IPv4 é suportado nesta versão.")
            if network.prefixlen < 24:
                raise ValueError("A versão 1.0 permite redes de até /24.")
            return str(network), int(network.num_addresses)
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError("Somente IPv4 é suportado nesta versão.")
        return str(address), 1
    except ValueError as exc:
        raise ValueError(f"Alvo de discovery inválido: {exc}") from exc


def _parse_xml(xml_text: str, dns_config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        reason = (status.get("reason") or "").lower()
        if reason not in _ALLOWED_REASONS:
            continue
        ipv4 = None
        mac = None
        vendor = None
        for address in node.findall("address"):
            if address.get("addrtype") == "ipv4":
                ipv4 = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor") or None
        if not ipv4:
            continue
        hostname = None
        names = node.find("hostnames")
        if names is not None:
            preferred = names.find("hostname")
            if preferred is not None:
                hostname = preferred.get("name")
        dns_result = resolve_ptr(ipv4, dns_config) if dns_config and dns_config.get("enabled") else {}
        dns_name = dns_result.get("dns_name")
        resolved_hostname = dns_result.get("hostname")
        final_hostname = resolved_hostname or hostname
        hostname_source = dns_result.get("hostname_source") or ("nmap" if hostname else None)
        hosts.append({
            "ip_address": ipv4,
            "mac_address": mac,
            "hostname": final_hostname,
            "dns_name": dns_name or hostname,
            "hostname_source": hostname_source,
            "vendor": vendor,
            "status": "up",
            "reason": reason,
            "dns_server": dns_result.get("dns_server"),
            "dns_error": dns_result.get("dns_error"),
        })
    return hosts


class NmapDiscoveryExecutor:
    name = "nmap_discovery"

    def __init__(self, nmap_path: str | None = None) -> None:
        self.nmap_path = nmap_path

    def run(self, job: dict[str, Any], workdir: str, timeout_seconds: int) -> ExecutionResult:
        started = datetime.now(timezone.utc)
        payload = job.get("payload") or {}
        target, address_count = _validate_target(str(payload.get("target") or job.get("target") or ""))
        nmap = find_nmap(payload.get("nmap_path") or self.nmap_path)
        if not nmap:
            raise RuntimeError("Nmap não encontrado. Instale o Nmap no Windows do Runner e reinicie o serviço.")
        dns_config = payload.get("dns") or {}
        args = [nmap, "-sn", "-T4", "--max-retries", "1", "--reason"]
        if dns_config.get("enabled"):
            args.append("-n")
        args += ["-oX", "-", target]
        try:
            proc = subprocess.run(args, cwd=workdir, capture_output=True, text=True, timeout=timeout_seconds, shell=False)
            finished = datetime.now(timezone.utc)
            xml_text = proc.stdout or ""
            hosts = _parse_xml(xml_text, dns_config) if proc.returncode == 0 and xml_text.strip() else []
            Path(workdir, "nmap.xml").write_text(xml_text, encoding="utf-8")
            Path(workdir, "hosts.json").write_text(json.dumps(hosts, indent=2, ensure_ascii=False), encoding="utf-8")
            return ExecutionResult(
                status="success" if proc.returncode == 0 else "failed",
                exit_code=proc.returncode,
                stdout=xml_text,
                stderr=proc.stderr or "",
                started_at=started.isoformat(), finished_at=finished.isoformat(),
                duration_seconds=(finished-started).total_seconds(),
                metadata={"provider":"runner", "target":target, "addresses_checked":address_count, "hosts":hosts, "raw_xml":xml_text, "nmap_path":nmap, "args":args, "dns": {"enabled": bool(dns_config.get("enabled")), "servers": dns_config.get("servers") or [], "suffix": dns_config.get("suffix") or "", "fallback_system": bool(dns_config.get("fallback_system", True))}},
            )
        except subprocess.TimeoutExpired as exc:
            finished = datetime.now(timezone.utc)
            return ExecutionResult(status="timeout", exit_code=None,
                stdout=exc.stdout.decode(errors="replace") if isinstance(exc.stdout,bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode(errors="replace") if isinstance(exc.stderr,bytes) else (exc.stderr or ""),
                started_at=started.isoformat(), finished_at=finished.isoformat(), duration_seconds=(finished-started).total_seconds(),
                metadata={"provider":"runner", "target":target, "addresses_checked":address_count, "hosts":[], "timeout":timeout_seconds, "nmap_path":nmap})
