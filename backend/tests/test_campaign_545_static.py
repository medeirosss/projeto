
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def test_attack_path_counts_confirmed_assets():
    s=(ROOT/'backend/app/services/attack_campaign_service.py').read_text()
    assert "confirmed_assets=" in s
    assert "'access_confirmed':len(confirmed_assets)" in s

def test_discovery_not_classified_as_access():
    s=(ROOT/'backend/app/services/attack_campaign_service.py').read_text()
    relation_pos=s.index("if relation=='discovery':")
    access_pos=s.index("if st=='confirmed'", relation_pos)
    assert relation_pos < access_pos

def test_evidence_ui_has_target_and_semantic_badges():
    s=(ROOT/'frontend/attack-simulator.js').read_text()
    assert "<strong>Target:</strong>" in s
    assert "ap-badge-success" in s
    assert "✓ DISCOVERY CONFIRMED" in s
    assert "✓ ACCESS CONFIRMED" in s
