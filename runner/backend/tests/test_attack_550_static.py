from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_catalog_contains_metaploit_four_domains():
    s=(ROOT/"backend/app/services/attack_simulator_service.py").read_text()
    for key in ("MAGI-M-ATK-END-001","MAGI-M-ATK-AD-001","MAGI-M-ATK-APP-001","MAGI-M-ATK-NET-001"):
        assert key in s
    assert '"provider": "metasploit"' in s

def test_metasploit_is_attack_simulation_job():
    s=(ROOT/"backend/app/services/validation_engine_service.py").read_text()
    assert '{"attack_simulation","metasploit"}' in s

def test_ui_split_and_history_provider():
    h=(ROOT/"frontend/attack-simulator.html").read_text()
    j=(ROOT/"frontend/attack-simulator.js").read_text()
    assert 'data-view="attack"' in h and 'data-view="campaign"' in h and 'data-view="history"' in h
    assert "Metasploit" in h and "Provider" in h
    assert "switchAttackView" in j and "providerLabel" in j
