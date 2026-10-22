from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
ROUTER=(ROOT/'backend/app/routers/attack_simulator.py').read_text(encoding='utf-8')
JS=(ROOT/'frontend/attack-simulator.js').read_text(encoding='utf-8')

def test_correlation_targets_include_web_assets():
    assert 'list_web_assets' in ROUTER
    assert "'asset_source':'web'" in ROUTER
    assert "'asset_type':'Web'" in ROUTER

def test_web_plan_is_supported():
    assert '_web_correlation_plan' in ROUTER
    assert "startswith('WEB-')" in ROUTER
    assert "str(task.get('category') or '').lower()!='application'" in ROUTER

def test_web_execution_uses_url_not_resolved_ip():
    assert "target=plan['target']['ip_address']" in ROUTER
    assert "'asset_ref':target_uuid" in ROUTER

def test_frontend_labels_web_assets():
    assert "x.asset_type==='Web'?'WEB':'HOST'" in JS
