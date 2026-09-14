import socket
import pytest

from magi_runner.executors import metasploit as msf


def test_runner_resolves_hostname_and_preserves_vhost(monkeypatch):
    def fake_getaddrinfo(host, port, family, socktype):
        assert host == "ad360centric.s3-website-us-east-1.amazonaws.com"
        assert port == 80
        assert family == socket.AF_INET
        assert socktype == socket.SOCK_STREAM
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("52.216.220.13", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("54.231.232.173", 80)),
        ]

    monkeypatch.setattr(msf.socket, "getaddrinfo", fake_getaddrinfo)
    r = msf._resolve_application_host("ad360centric.s3-website-us-east-1.amazonaws.com", 80)
    assert r["resolved_ip"] == "52.216.220.13"
    assert r["resolved_addresses"] == ["52.216.220.13", "54.231.232.173"]
    assert r["dns_resolution"] == "runner"
    assert r["vhost_required"] is True


def test_ip_literal_does_not_require_dns_or_vhost(monkeypatch):
    monkeypatch.setattr(msf.socket, "getaddrinfo", lambda *args: (_ for _ in ()).throw(AssertionError("DNS must not run")))
    r = msf._resolve_application_host("192.0.2.10", 80)
    assert r["resolved_ip"] == "192.0.2.10"
    assert r["dns_resolution"] == "not_required"
    assert r["vhost_required"] is False


def test_dns_failure_is_explicit(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror(11001, "getaddrinfo failed")
    monkeypatch.setattr(msf.socket, "getaddrinfo", fail)
    with pytest.raises(RuntimeError, match="DNS_RESOLUTION_FAILED"):
        msf._resolve_application_host("does-not-resolve.example", 80)
