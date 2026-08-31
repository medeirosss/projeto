from __future__ import annotations
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

def _runner_root() -> Path:
    return Path(__file__).resolve().parents[2]

def _sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def bundled_paths() -> tuple[Path,Path,Path]:
    root=_runner_root()/"tools"/"nuclei"
    return root/"nuclei.exe", root/"templates", root/"runtime-manifest.json"

def candidate_binaries(configured_path: str|None=None)->list[str]:
    bundled,_,_=bundled_paths()
    vals=[configured_path,os.environ.get("MAGI_NUCLEI_PATH"),str(bundled),shutil.which("nuclei"),
          r"C:\Program Files\Magi\Runner\tools\nuclei\nuclei.exe",
          r"C:\Program Files\Magi Runner\tools\nuclei\nuclei.exe"]
    out=[]
    for v in vals:
        if v and v not in out: out.append(str(v))
    return out

def _integrity(binary:Path|None,templates:Path,manifest_path:Path)->dict[str,Any]:
    result={"status":"unknown","manifest_path":str(manifest_path),"checks":[]}
    if not manifest_path.is_file():
        result["status"]="manifest_missing"; return result
    try:
        manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.update(status="manifest_invalid",error=str(exc)); return result
    expected=((manifest.get("nuclei_exe") or {}).get("sha256") or "").lower()
    if binary and binary.is_file() and expected:
        actual=_sha256(binary).lower()
        result["checks"].append({"name":"nuclei_exe_sha256","ok":actual==expected,"expected":expected,"actual":actual})
    else:
        result["checks"].append({"name":"nuclei_exe_sha256","ok":False,"reason":"binary_or_hash_missing"})
    checksum=templates/"templates-checksum.txt"
    texp=((manifest.get("templates") or {}).get("templates_checksum_file_sha256") or "").lower()
    if checksum.is_file() and texp:
        actual=_sha256(checksum).lower()
        result["checks"].append({"name":"templates_checksum_marker","ok":actual==texp,"expected":texp,"actual":actual})
    else:
        result["checks"].append({"name":"templates_checksum_marker","ok":False,"reason":"checksum_marker_or_hash_missing"})
    result["status"]="ok" if result["checks"] and all(x.get("ok") for x in result["checks"]) else "failed"
    result["runtime_policy"]=manifest.get("runtime_policy")
    result["auto_update"]=manifest.get("auto_update")
    result["manifest"]=manifest
    return result

def nuclei_capability(configured_path:str|None=None,templates_path:str|None=None)->dict[str,Any]:
    searched=candidate_binaries(configured_path)
    binary=next((Path(p) for p in searched if Path(p).is_file()),None)
    _,bundled_templates,manifest_path=bundled_paths()
    templates=Path(templates_path or os.environ.get("MAGI_NUCLEI_TEMPLATES") or str(bundled_templates))
    templates_ok=templates.is_dir() and any(templates.rglob("*.yaml"))
    integrity=_integrity(binary,templates,manifest_path)
    return {
        "engine":"ready" if binary else "unavailable",
        "engine_available":bool(binary),
        "binary_path":str(binary) if binary else None,
        "searched_paths":searched,
        "templates":"ready" if templates_ok else "unavailable",
        "templates_available":bool(templates_ok),
        "templates_path":str(templates),
        "runtime_integrity":integrity,
        "runtime_policy":integrity.get("runtime_policy") or "fixed_bundled",
        "ready":bool(binary and templates_ok and integrity.get("status")=="ok"),
    }
