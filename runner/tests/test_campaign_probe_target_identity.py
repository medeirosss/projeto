from magi_runner.executors import campaign_probe as cp

def test_rejects_ttl_from_different_ip(monkeypatch):
    class P:
        returncode=0; stdout="Resposta de 192.168.0.1: bytes=32 tempo<1ms TTL=64\n"; stderr=""
    monkeypatch.setattr(cp.subprocess,"run",lambda *a,**k:P())
    assert cp._icmp_alive("192.168.0.25",2) is False

def test_accepts_ttl_from_exact_target(monkeypatch):
    class P:
        returncode=0; stdout="Resposta de 192.168.0.25: bytes=32 tempo<1ms TTL=128\n"; stderr=""
    monkeypatch.setattr(cp.subprocess,"run",lambda *a,**k:P())
    assert cp._icmp_alive("192.168.0.25",2) is True
