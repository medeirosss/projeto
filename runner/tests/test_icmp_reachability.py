from types import SimpleNamespace
from unittest.mock import patch

from magi_runner.executors import security_check as sc


def _cp(stdout, returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_windows_real_echo_reply_is_reachable():
    output = "Disparando 192.168.0.100...\nResposta de 192.168.0.100: bytes=32 tempo<1ms TTL=128\n"
    with patch.object(sc.os, "name", "nt"), patch.object(sc.subprocess, "run", return_value=_cp(output)):
        result = sc._icmp_probe("192.168.0.100")
    assert result["reachable"] is True
    assert result["reply_from_target"] is True


def test_windows_gateway_unreachable_is_not_reachable():
    output = "Resposta de 192.168.0.1: Host de destino inacessível.\n"
    with patch.object(sc.os, "name", "nt"), patch.object(sc.subprocess, "run", return_value=_cp(output, 0)):
        result = sc._icmp_probe("192.168.0.87")
    assert result["reachable"] is False
    assert result["reply_from_target"] is False


def test_windows_timeout_is_not_reachable():
    output = "Esgotado o tempo limite do pedido.\n"
    with patch.object(sc.os, "name", "nt"), patch.object(sc.subprocess, "run", return_value=_cp(output, 1)):
        result = sc._icmp_probe("192.168.0.87")
    assert result["reachable"] is False
