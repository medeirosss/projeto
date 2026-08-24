from pathlib import Path
from unittest.mock import patch
from magi_runner.core.nuclei_capability import nuclei_capability, bundled_paths

def test_bundled_nuclei_capability_is_ready():
    cap=nuclei_capability()
    assert cap["engine_available"] is True
    assert cap["templates_available"] is True
    assert cap["runtime_integrity"]["status"]=="ok"
    assert cap["runtime_policy"]=="fixed_bundled"
    assert cap["ready"] is True

def test_missing_runtime_is_unavailable(tmp_path):
    missing_root=tmp_path/"missing"
    with patch("magi_runner.core.nuclei_capability.bundled_paths", return_value=(missing_root/"nuclei.exe",missing_root/"templates",missing_root/"runtime-manifest.json")), \
         patch("magi_runner.core.nuclei_capability.shutil.which", return_value=None):
        cap=nuclei_capability()
    assert cap["engine"]=="unavailable"
    assert cap["templates"]=="unavailable"
    assert cap["ready"] is False
