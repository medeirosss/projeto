from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_automatic_planner_is_data_driven():
    s=(ROOT/'backend/app/services/automatic_correlation_service.py').read_text(encoding='utf-8')
    assert 'correlate_target' in s and "list_tasks('magi_attack'" in s
    assert 'MAGI-ATK-END-005' not in s
    assert "credential_requirement']=='NONE'" in s
def test_router_uses_automatic_planner():
    s=(ROOT/'backend/app/routers/attack_simulator.py').read_text(encoding='utf-8')
    assert 'automatic_correlation_service import build_plan' in s
def test_service_conditions_accept_deep_inventory_services():
    s=(ROOT/'backend/app/services/attack_exposure_service.py').read_text(encoding='utf-8')
    assert 'deep_inventory_service' in s
