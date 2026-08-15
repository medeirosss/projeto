from magi_runner.core.nuclei_capability import nuclei_capability

def test_nuclei_capability_missing(tmp_path):
    cap=nuclei_capability(str(tmp_path/"missing.exe"), str(tmp_path/"missing-templates"))
    assert cap["engine"]=="unavailable"
    assert cap["templates"]=="unavailable"
    assert cap["ready"] is False
    assert cap["searched_paths"]

def test_nuclei_capability_ready(tmp_path):
    exe=tmp_path/"nuclei.exe"; exe.write_text("x")
    templates=tmp_path/"templates"; templates.mkdir()
    cap=nuclei_capability(str(exe), str(templates))
    assert cap["engine_available"] is True
    assert cap["templates_available"] is True
    assert cap["ready"] is True
