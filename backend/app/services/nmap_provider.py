from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


class DiscoveryInputError(ValueError):
    pass


class DiscoveryExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscoveredHost:
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None


def validate_target_spec(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise DiscoveryInputError("Informe um IPv4 ou uma rede CIDR.")
    try:
        parsed = ipaddress.ip_network(raw, strict=False) if "/" in raw else ipaddress.ip_address(raw)
    except ValueError as exc:
        raise DiscoveryInputError("Alvo inválido. Use um IPv4 individual ou CIDR IPv4.") from exc
    if parsed.version != 4:
        raise DiscoveryInputError("Nesta sprint, somente IPv4 é suportado.")
    if isinstance(parsed, ipaddress.IPv4Network) and parsed.num_addresses > 65536:
        raise DiscoveryInputError("A rede informada é muito ampla. O limite inicial é /16 (65.536 endereços).")
    return str(parsed)


def _parse_nmap_xml(xml_output: str) -> list[DiscoveredHost]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise DiscoveryExecutionError("O Nmap retornou XML inválido.") from exc

    hosts: list[DiscoveredHost] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip_address = None
        mac_address = None
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip_address = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac_address = address.get("addr")
        if not ip_address:
            continue
        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name") or None
        hosts.append(DiscoveredHost(ip_address=ip_address, hostname=hostname, mac_address=mac_address))
    return hosts


class LocalNmapProvider:
    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds

    def discover(self, target_spec: str) -> list[DiscoveredHost]:
        validated = validate_target_spec(target_spec)
        if not shutil.which("nmap"):
            raise DiscoveryExecutionError("Nmap não encontrado na imagem do backend.")
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-oX", "-", validated],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DiscoveryExecutionError(f"A descoberta excedeu {self.timeout_seconds} segundos.") from exc
        except OSError as exc:
            raise DiscoveryExecutionError(f"Falha ao iniciar o Nmap: {exc}") from exc
        if result.returncode != 0:
            error = (result.stderr or "Falha desconhecida ao executar o Nmap.").strip()
            raise DiscoveryExecutionError(error[:1000])
        return _parse_nmap_xml(result.stdout)
