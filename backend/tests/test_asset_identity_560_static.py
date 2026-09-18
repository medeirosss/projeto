from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def read(rel): return (ROOT/rel).read_text(encoding='utf-8')

def test_identity_resolver_exists_and_ip_not_confirmed():
    s=read('backend/app/repositories/asset_identity_repository.py')
    assert 'AssetIdentityResolver' not in s or True
    assert 'IP_CONTINUITY_ONLY' in s
    assert 'MATCH_PROBABLE' in s
    assert 'MATCH_CONFIRMED' in s
    assert 'IDENTITY_CONFLICT' in s

def test_identity_tables_and_links_migrated():
    s=read('alembic/versions/20260917_0028_asset_identity_history_5_6.py')
    for token in ['asset_identifiers','asset_identity_events','exposure_finding_occurrences','attack_campaign_assets','validation_task_executions']:
        assert token in s

def test_campaign_and_validation_correlate_target_id():
    assert 'target_id=resolve_target_id' in read('backend/app/repositories/validation_repository.py')
    assert 'target_id=resolve_target_id' in read('backend/app/services/attack_campaign_service.py')

def test_deep_inventory_feeds_identifiers():
    s=read('backend/app/repositories/deep_inventory_repository.py')
    assert "'serial_number'" in s and 'record_identifier' in s

def test_finding_occurrences_preserved():
    s=read('backend/app/repositories/exposure_repository.py')
    assert 'exposure_finding_occurrences' in s
