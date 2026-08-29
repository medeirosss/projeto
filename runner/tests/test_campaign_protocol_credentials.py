from magi_runner.executors import credential_validate as cv

def test_snmp_relation_is_discovery(monkeypatch,tmp_path):
    monkeypatch.setattr(cv,'_snmp_validate',lambda *a:(True,'switch-lab','snmp_v2c',1,''))
    r=cv.CredentialValidateExecutor().run({'target':'192.0.2.10','payload':{'target':'192.0.2.10','credential_type':'snmp_v2c','credential_id':9,'credential':{'type':'snmp_v2c','secret':'lab'},'campaign_context':{'campaign_uuid':'camp-test'}}},str(tmp_path),10)
    assert r.metadata['authenticated'] is True
    assert r.metadata['relation_type']=='discovery'

def test_smb_forced_protocol(monkeypatch,tmp_path):
    monkeypatch.setattr(cv,'_smb_validate',lambda *a:(True,'192.0.2.20','smb',1,''))
    r=cv.CredentialValidateExecutor().run({'target':'192.0.2.20','payload':{'target':'192.0.2.20','protocol':'smb','credential_type':'windows','credential_id':1,'credential':{'type':'windows','username':'u','secret':'p'}}},str(tmp_path),10)
    assert r.metadata['authenticated'] is True
    assert r.metadata['protocol']=='smb'
    assert r.metadata['relation_type']=='access'
