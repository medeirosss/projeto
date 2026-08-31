from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
from typing import Any


def _encode_name(name: str) -> bytes:
    parts = [part.encode("ascii") for part in name.strip(".").split(".") if part]
    return b"".join(bytes([len(part)]) + part for part in parts) + b"\x00"


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 20:
        raise ValueError("DNS compression loop")
    labels: list[str] = []
    original_offset = offset
    jumped = False
    while True:
        if offset >= len(data):
            raise ValueError("DNS response truncated")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS pointer truncated")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = _read_name(data, pointer, depth + 1)
            labels.append(pointed)
            offset += 2
            jumped = True
            break
        offset += 1
        label = data[offset:offset + length]
        labels.append(label.decode("ascii", errors="replace"))
        offset += length
    return ".".join(filter(None, labels)), offset if jumped else offset


def query_ptr(ip_address: str, server: str, timeout_seconds: int = 2) -> str | None:
    ip = ipaddress.ip_address(ip_address)
    if ip.version != 4:
        return None
    reverse_name = ".".join(reversed(ip_address.split("."))) + ".in-addr.arpa"
    txid = random.randint(0, 65535)
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(reverse_name) + struct.pack("!HH", 12, 1)

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(max(1, min(10, int(timeout_seconds))))
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)

    if len(data) < 12:
        return None
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if response_id != txid or flags & 0x000F:
        return None
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            return None
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if rtype == 12 and rclass == 1:
            name, _ = _read_name(data, rdata_offset)
            return name.rstrip(".") or None
    return None


def resolve_ptr(ip_address: str, config: dict[str, Any] | None) -> dict[str, Any]:
    config = config or {}
    if not config.get("enabled"):
        return {"dns_name": None, "hostname": None, "hostname_source": None, "dns_error": None}

    timeout = max(1, min(10, int(config.get("timeout_seconds") or 2)))
    servers = [str(item).strip() for item in (config.get("servers") or []) if str(item).strip()]
    errors: list[str] = []
    for server in servers[:2]:
        try:
            name = query_ptr(ip_address, server, timeout)
            if name:
                suffix = str(config.get("suffix") or "").strip().strip(".")
                dns_name = f"{name}.{suffix}" if suffix and "." not in name else name
                return {
                    "dns_name": dns_name,
                    "hostname": name.split(".", 1)[0],
                    "hostname_source": "dns_ptr",
                    "dns_server": server,
                    "dns_error": None,
                }
        except Exception as exc:
            errors.append(f"{server}: {exc}")

    if config.get("fallback_system", True):
        try:
            name = socket.gethostbyaddr(ip_address)[0].rstrip(".")
            if name:
                suffix = str(config.get("suffix") or "").strip().strip(".")
                dns_name = f"{name}.{suffix}" if suffix and "." not in name else name
                return {
                    "dns_name": dns_name,
                    "hostname": name.split(".", 1)[0],
                    "hostname_source": "system_dns_ptr",
                    "dns_server": "system",
                    "dns_error": None,
                }
        except Exception as exc:
            errors.append(f"system: {exc}")

    return {
        "dns_name": None,
        "hostname": None,
        "hostname_source": None,
        "dns_error": "; ".join(errors)[:500] if errors else "PTR não encontrado",
    }
