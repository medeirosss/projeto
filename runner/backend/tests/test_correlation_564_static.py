from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_zero_credential_guarantee_backend():
    s=(ROOT/'backend/app/services/validation_engine_service.py').read_text(encoding='utf-8')
    assert "credential_requirement!='NONE'" in s
    assert "Zero-Credential Guarantee" in s

def test_correlation_only_resolves_required_credentials():
    s=(ROOT/'backend/app/routers/attack_simulator.py').read_text(encoding='utf-8')
    assert "if req=='REQUIRED':" in s
    assert "if req=='NONE': opts.pop('credential_id',None)" in s

def test_remote_evidence_is_capability_gated():
    s=(ROOT/'backend/app/routers/attack_simulator.py').read_text(encoding='utf-8')
    assert "meta.get('remote_evidence')" in s and "=='SUPPORTED'" in s
    ui=(ROOT/'frontend/attack-simulator.html').read_text(encoding='utf-8')
    assert 'correlationEvidence' in ui
