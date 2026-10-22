from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_application_url_field_and_payload_selection():
    h=(ROOT/"frontend/attack-simulator.html").read_text()
    j=(ROOT/"frontend/attack-simulator.js").read_text()
    assert 'id="attackUrl"' in h
    assert "isApplication" in j
    assert "document.getElementById('attackUrl').value.trim()" in j

def test_application_catalog_marks_url_target():
    s=(ROOT/"backend/app/services/attack_simulator_service.py").read_text()
    start=s.index('"task_key": "MAGI-M-ATK-APP-001"')
    block=s[start:start+2200]
    assert '"target_type": "url"' in block
    assert '"supported_schemes": ["http", "https"]' in block
