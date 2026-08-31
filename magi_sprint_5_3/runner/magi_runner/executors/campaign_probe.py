from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import ExecutionResult


def _tcp_open(target: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


def _icmp_alive(target: str, timeout_seconds: int) -> bool:
    # Windows Runner. One echo only; failure is not considered proof that the host is down.
    try:
        ms = max(250, min(1500, int(timeout_seconds * 1000)))
        p = subprocess.run(
            ["ping", "-n", "1", "-w", str(ms), target],
            capture_output=True,
            text=True,
            timeout=max(2, timeout_seconds + 1),
            shell=False,
        )
        return p.returncode == 0
    except Exception:
        return False


def _ber_len(n: int) -> bytes:
    return bytes([n]) if n < 128 else bytes([0x81, n])


def _ber(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ber(0x02, raw)


def _ber_oid(parts: list[int]) -> bytes:
    first = bytes([40 * parts[0] + parts[1]])
    out = bytearray(first)
    for n in parts[2:]:
        stack = [n & 0x7F]
        n >>= 7
        while n:
            stack.append((n & 0x7F) | 0x80)
            n >>= 7
        out.extend(reversed(stack))
    return _ber(0x06, bytes(out))


def _snmp_sysname(target: str, community: str, timeout: float = 1.5) -> tuple[bool, str | None, str | None]:
    if not community:
        return False, None, None
    req_id = 0x4D414749
    oid = [1, 3, 6, 1, 2, 1, 1, 5, 0]
    vb = _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
    vbl = _ber(0x30, vb)
    pdu = _ber(0xA0, _ber_int(req_id) + _ber_int(0) + _ber_int(0) + vbl)
    msg = _ber(0x30, _ber_int(1) + _ber(0x04, community.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (target, 161))
        data, _ = s.recvfrom(65535)
        strings: list[str] = []

        def walk(buf: bytes, start: int = 0, end: int | None = None) -> None:
            end = len(buf) if end is None else end
            i = start
            while i + 2 <= end:
                tag = buf[i]
                i += 1
                length = buf[i]
                i += 1
                if length & 0x80:
                    count = length & 0x7F
                    if i + count > end:
                        return
                    length = int.from_bytes(buf[i : i + count], "big")
                    i += count
                if i + length > end:
                    return
                val = buf[i : i + length]
                if tag == 0x04:
                    try:
                        txt = val.decode("utf-8").strip()
                        if txt and txt != community and all(ch.isprintable() for ch in txt):
                            strings.append(txt)
                    except Exception:
                        pass
                if tag in (0x30, 0xA0, 0xA2):
                    walk(val, 0, len(val))
                i += length

        walk(data)
        hostname = strings[-1] if strings else None
        return True, hostname, None
    except Exception as exc:
        return False, None, str(exc)
    finally:
        s.close()


class CampaignProbeExecutor:
    """Cheap existence/service precondition for Attack Campaign.

    One probe replaces the previous WinRM+SMB+SSH+SNMP fan-out against every
    candidate address. Credentials are never used as generic host-discovery
    mechanisms; the optional SNMP community is used only to positively detect
    devices whose useful management surface is UDP/161.
    """

    name = "campaign_probe"

    def run(self, job: dict[str, Any], workdir: str, timeout_seconds: int) -> ExecutionResult:
        started = datetime.now(timezone.utc)
        payload = job.get("payload") or {}
        target = str(payload.get("target") or job.get("target") or "").strip()
        ipaddress.ip_address(target)

        enabled = set(payload.get("enabled_vectors") or [])
        ports: list[int] = []
        if "ssh" in enabled:
            ports.append(22)
        if "smb" in enabled:
            ports.append(445)
        if "winrm" in enabled:
            ports.extend([5985, 5986])
        ports = sorted(set(ports))

        open_ports = [p for p in ports if _tcp_open(target, p, timeout=min(1.2, max(0.4, timeout_seconds / 10)))]
        icmp = _icmp_alive(target, min(2, max(1, timeout_seconds)))

        cred = payload.get("credential") or {}
        snmp_confirmed = False
        snmp_hostname = None
        snmp_error = None
        if "snmp_v2c" in enabled and str(cred.get("secret") or ""):
            snmp_confirmed, snmp_hostname, snmp_error = _snmp_sysname(
                target, str(cred.get("secret") or ""), timeout=min(1.5, max(0.5, timeout_seconds / 8))
            )

        alive = bool(icmp or open_ports or snmp_confirmed)
        applicable: list[str] = []
        if 22 in open_ports and "ssh" in enabled:
            applicable.append("ssh")
        if 445 in open_ports and "smb" in enabled:
            applicable.append("smb")
        if ({5985, 5986} & set(open_ports)) and "winrm" in enabled:
            applicable.append("winrm")
        if snmp_confirmed and "snmp_v2c" in enabled:
            applicable.append("snmp_v2c")

        finished = datetime.now(timezone.utc)
        confirmation = "discovery_confirmed" if alive else "discovery_not_confirmed"
        metadata = {
            "target": target,
            "hostname": snmp_hostname,
            "alive": alive,
            "icmp": icmp,
            "open_ports": open_ports,
            "applicable_protocols": applicable,
            "snmp_confirmed": snmp_confirmed,
            "snmp_error": snmp_error,
            "protocol": "preflight",
            "relation_type": "discovery",
            "authenticated": False,
            "executed_real_test": True,
            "execution_scope": "campaign_remote",
            "campaign_context": payload.get("campaign_context") or {},
            "attack_result": confirmation,
            "confirmation_status": confirmation,
            "finding": {
                "status": confirmation,
                "detected": alive,
                "message": (
                    f"Host {target} detectado; protocolos aplicáveis: {', '.join(applicable) or 'nenhum vetor habilitado'}."
                    if alive
                    else f"Host {target} não respondeu ao preflight da Campaign."
                ),
            },
        }
        Path(workdir, "campaign_probe.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        return ExecutionResult(
            status="success",
            exit_code=0,
            stdout=json.dumps(metadata, ensure_ascii=False),
            stderr="",
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=(finished - started).total_seconds(),
            metadata=metadata,
        )
