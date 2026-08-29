from magi_runner.executors import campaign_probe as cp
from magi_runner.executors.credential_validate import _failure_status


def test_preflight_offline_does_not_detect(monkeypatch,tmp_path):
    monkeypatch.setattr(cp,'_tcp_open',lambda *a,**k:False)
    monkeypatch.setattr(cp,'_icmp_alive',lambda *a,**k:False)
    monkeypatch.setattr(cp,'_snmp_sysname',lambda *a,**k:(False,None,'timed out'))
    r=cp.CampaignProbeExecutor().run({'target':'192.0.2.10','payload':{'target':'192.0.2.10','enabled_vectors':['winrm','smb','ssh','snmp_v2c'],'credential':{'secret':'public'}}},str(tmp_path),6)
    assert r.metadata['alive'] is False
    assert r.metadata['applicable_protocols']==[]
    assert r.metadata['confirmation_status']=='discovery_not_confirmed'


def test_preflight_only_returns_applicable_services(monkeypatch,tmp_path):
    monkeypatch.setattr(cp,'_tcp_open',lambda target,port,timeout=1.2: port in {22,445})
    monkeypatch.setattr(cp,'_icmp_alive',lambda *a,**k:True)
    monkeypatch.setattr(cp,'_snmp_sysname',lambda *a,**k:(False,None,None))
    r=cp.CampaignProbeExecutor().run({'target':'192.0.2.20','payload':{'target':'192.0.2.20','enabled_vectors':['winrm','smb','ssh']}},str(tmp_path),6)
    assert r.metadata['alive'] is True
    assert set(r.metadata['applicable_protocols'])=={'ssh','smb'}
    assert 'winrm' not in r.metadata['applicable_protocols']


def test_failure_classes():
    assert _failure_status('ssh','Dependência paramiko não encontrada no Runner.',0)=='runner_dependency_missing'
    assert _failure_status('winrm','FullyQualifiedErrorId : ServerNotTrusted,PSSessionStateBroken',1)=='transport_failed'
    assert _failure_status('smb','O domínio não está disponível',1)=='transport_failed'
    assert _failure_status('ssh','Authentication failed.',2)=='authentication_failed'
