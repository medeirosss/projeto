import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def test_knowledge_004_forces_refresh_and_end005_is_executable():
    d=json.loads((ROOT/'backend/app/data/attack_knowledge_2026.09.004.json').read_text(encoding='utf-8'))
    assert d['manifest']['knowledge_version']=='2026.09.004'
    a=next(x for x in d['attacks'] if x['attack_uuid']=='MAGI-KB-000015')
    t=next(x for x in a['techniques'] if x['technique_key']=='MAGI-ATK-END-005')
    assert t['executable'] is True and t['provider']=='magi_native' and t['simulation_impact']=='SAFE'

def test_importer_accepts_mapping_schema_and_bundled_004():
    s=(ROOT/'backend/app/services/attack_knowledge_service.py').read_text(encoding='utf-8')
    assert 'attack_knowledge_2026.09.004.json' in s
    assert "tech.get('executable', True)" in s
    assert "tech.get('simulation_impact') or tech.get('impact')" in s

def test_correlation_is_exposure_driven_not_end005_hardcoded():
    s=(ROOT/'backend/app/services/automatic_correlation_service.py').read_text(encoding='utf-8')
    assert 'correlate_target' in s
    assert "attack.get('simulations'" in s
    assert 'MAGI-ATK-END-005' not in s
