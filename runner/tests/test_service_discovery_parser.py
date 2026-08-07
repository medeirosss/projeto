from pathlib import Path
from magi_runner.executors.service_discovery import _parse


def test_windows_service_discovery_fixture():
    fixture = Path(__file__).parent / "fixtures" / "service_discovery_windows.xml"
    services = _parse(fixture.read_text(encoding="utf-8"))
    assert [item["port"] for item in services] == [135, 139, 445, 6565]
    assert services[0]["product"] == "Microsoft Windows RPC"
    assert services[0]["os_type"] == "Windows"
    assert services[0]["cpe"] == ["cpe:/o:microsoft:windows"]
    assert services[2]["service_name"] == "microsoft-ds"
    assert services[3]["service_name"] == "unknown"
    assert services[3]["tunnel"] == "ssl"
