from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def test_snapshot_contract():
    d=json.loads((ROOT/'backend/app/data/attack_knowledge_2026.09.001.json').read_text())
    assert d['manifest']['full_snapshot'] is True
    assert d['manifest']['knowledge_schema']==1
    assert d['manifest']['minimum_magi_version']=='5.6.1'
    assert len(d['attacks'])>=10
    impacts={x['impact'] for x in d['attacks']}
    assert {'SAFE','LOW','MEDIUM','HIGH'} <= impacts
def test_high_is_informational_only():
    d=json.loads((ROOT/'backend/app/data/attack_knowledge_2026.09.001.json').read_text())
    for a in d['attacks']:
        if a['impact']=='HIGH': assert not any(t.get('executable') for t in a.get('techniques',[]))
def test_full_snapshot_importer_and_tables():
    s=(ROOT/'backend/app/services/attack_knowledge_service.py').read_text()
    assert 'full snapshot cumulativo' in s
    assert "status='deprecated'" in s
    m=(ROOT/'alembic/versions/20260918_0029_attack_knowledge_5_6_1.py').read_text()
    for table in ('attack_knowledge','attack_conditions','attack_cve_mappings','attack_references','attack_technique_mappings','knowledge_sync_history','knowledge_state'): assert table in m
def test_router_wired():
    s=(ROOT/'backend/main.py').read_text()
    assert 'attack_knowledge_router' in s and 'ensure_bundled_knowledge()' in s
