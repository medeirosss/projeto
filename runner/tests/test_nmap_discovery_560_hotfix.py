from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

from magi_runner.executors.nmap_discovery import NmapDiscoveryExecutor
from magi_runner.utils.dns_resolver import resolve_ptr


XML = '''<?xml version="1.0"?><nmaprun><host><status state="up" reason="echo-reply"/><address addr="192.168.0.10" addrtype="ipv4"/></host><runstats/></nmaprun>'''


def test_system_ptr_fallback_is_bounded():
    def blocked(_ip):
        time.sleep(2)
        return ("late.example", [], [])
    started = time.monotonic()
    with patch("magi_runner.utils.dns_resolver.socket.gethostbyaddr", side_effect=blocked):
        result = resolve_ptr("192.168.0.10", {"enabled": True, "servers": [], "fallback_system": True, "system_timeout_seconds": 0.5})
    assert time.monotonic() - started < 1.2
    assert "timeout" in (result.get("dns_error") or "").lower()


def test_raw_nmap_xml_is_persisted_before_enrichment(tmp_path):
    cp = type("CP", (), {"returncode": 0, "stdout": XML, "stderr": ""})()
    executor = NmapDiscoveryExecutor(nmap_path=str(tmp_path / "nmap.exe"))
    (tmp_path / "nmap.exe").write_text("fake")
    with patch("magi_runner.executors.nmap_discovery.find_nmap", return_value=str(tmp_path / "nmap.exe")), \
         patch("magi_runner.executors.nmap_discovery.subprocess.run", return_value=cp), \
         patch("magi_runner.executors.nmap_discovery._parse_xml", side_effect=RuntimeError("enrichment failed")):
        try:
            executor.run({"payload": {"target": "192.168.0.0/24", "dns": {"enabled": True}}}, str(tmp_path), 10)
        except RuntimeError:
            pass
    assert (tmp_path / "nmap.xml").read_text() == XML
