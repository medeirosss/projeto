from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_runner_target_join():
 s=(ROOT/'backend/app/repositories/attack_campaign_repository.py').read_text()
 assert 'j.target AS runner_target' in s and 'j.id=p.runner_job_id' in s
def test_evidence_ip():
 s=(ROOT/'backend/app/services/attack_campaign_service.py').read_text()
 assert "p.get('runner_target')" in s and "'target_ip':target" in s
def test_theme():
 for p in ('frontend/style.css','frontend/assets/style.css'):
  assert 'background:#172833;border:1px solid #2d414e' not in (ROOT/p).read_text()
