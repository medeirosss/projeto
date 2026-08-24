from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base import ExecutionResult
from .security_check import _reachability_preflight, _tcp_probe
from magi_runner.core.nuclei_capability import nuclei_capability


def _find_nuclei(payload: dict[str, Any]) -> str | None:
    return nuclei_capability(payload.get("nuclei_path"), payload.get("nuclei_templates_path")).get("binary_path")

def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    rows=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj=json.loads(line)
            if isinstance(obj,dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return rows


def _host_from_target(target: str) -> tuple[str, int | None, str | None]:
    raw=target.strip()
    if "://" in raw:
        parsed=urlparse(raw)
        return parsed.hostname or raw, parsed.port, parsed.scheme
    # IPv4/hostname:port
    if raw.count(":")==1:
        host,port=raw.rsplit(":",1)
        if port.isdigit():
            return host,int(port),None
    return raw,None,None


def _count_templates(path: Path) -> int:
    if path.is_file():
        return 1
    return sum(1 for _ in path.rglob("*.yaml")) + sum(1 for _ in path.rglob("*.yml"))


def _normalize_match(row: dict[str, Any]) -> dict[str, Any]:
    info=row.get("info") or {}
    template_id=row.get("template-id") or row.get("template_id") or row.get("template")
    severity=str(info.get("severity") or row.get("severity") or "unknown").lower()
    name=info.get("name") or row.get("name") or template_id
    matched_at=row.get("matched-at") or row.get("matched_at") or row.get("host")
    text=" ".join(str(x) for x in [template_id,name,matched_at] if x)
    cves=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}",text,re.IGNORECASE)))
    return {
        "template_id":template_id,
        "name":name,
        "severity":severity,
        "matched_at":matched_at,
        "matcher_name":row.get("matcher-name") or row.get("matcher_name"),
        "type":row.get("type"),
        "host":row.get("host"),
        "ip":row.get("ip"),
        "port":row.get("port"),
        "cves":[x.upper() for x in cves],
        "extracted_results":row.get("extracted-results") or row.get("extracted_results") or [],
        "curl_command":row.get("curl-command") or row.get("curl_command"),
    }


def _finish(
    *,
    started: datetime,
    status: str,
    exit_code: int,
    message: str,
    finding_status: str,
    evidence: dict[str, Any],
    target: str,
    executed: bool,
    stdout: str="",
    stderr: str="",
    duration: float | None=None,
) -> ExecutionResult:
    finished=datetime.now(timezone.utc)
    finding={
        "detected": True if finding_status=="detected" else False if finding_status in {"not_detected","not_applicable"} else None,
        "status":finding_status,
        "message":message,
    }
    metadata={
        "finding":finding,
        "evidence":evidence,
        "message":message,
        "confirmation_status":finding_status,
        "execution_scope":"runner_to_target",
        "requested_target":target,
        "executed_real_test":executed,
    }
    return ExecutionResult(
        status=status,exit_code=exit_code,stdout=stdout,stderr=stderr,
        started_at=started.isoformat(),finished_at=finished.isoformat(),
        duration_seconds=duration if duration is not None else (finished-started).total_seconds(),
        metadata=metadata,
    )


class NucleiExecutor:
    name="nuclei"

    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc)
        payload=job.get("payload") or {}
        target=str(payload.get("target") or job.get("target") or "").strip()
        template=str(payload.get("template") or payload.get("template_id") or "").strip()
        profile_name=str(payload.get("profile_name") or "Nuclei Validation")
        protocol=str(payload.get("protocol") or "http").lower()
        ports=[int(x) for x in (payload.get("ports") or []) if str(x).isdigit()]

        capability=nuclei_capability(payload.get("nuclei_path"),payload.get("nuclei_templates_path"))
        binary=capability.get("binary_path")
        template_root=Path(capability.get("templates_path") or "")
        if not target:
            raise ValueError("nuclei requer target")
        if not template:
            raise ValueError("nuclei requer template/template_id")

        base_evidence={
            "provider":"nuclei","profile":profile_name,"target":target,"template_id":template,
            "runtime_policy":capability.get("runtime_policy"),
            "runtime_integrity":(capability.get("runtime_integrity") or {}).get("status"),
        }

        if not binary:
            ev={**base_evidence,"reason":"engine_unavailable","infrastructure_status":"engine_unavailable","searched_paths":capability.get("searched_paths",[])}
            return _finish(started=started,status="failed",exit_code=127,message="Nuclei Engine indisponível no Runner.",
                           finding_status="not_evaluated",evidence=ev,target=target,executed=False,stderr="Nuclei Engine indisponível no Runner.")

        if (capability.get("runtime_integrity") or {}).get("status")!="ok":
            ev={**base_evidence,"reason":"runtime_integrity_failed","infrastructure_status":"runtime_integrity_failed",
                "integrity":capability.get("runtime_integrity")}
            return _finish(started=started,status="failed",exit_code=65,message="Integridade do runtime Nuclei não validada.",
                           finding_status="not_evaluated",evidence=ev,target=target,executed=False,stderr="Runtime integrity failed.")

        template_path=Path(template)
        if not template_path.is_absolute():
            template_path=template_root/template
        if not template_path.exists():
            ev={**base_evidence,"reason":"template_unavailable","infrastructure_status":"template_unavailable","template_path":str(template_path)}
            return _finish(started=started,status="failed",exit_code=66,message=f"Perfil Nuclei indisponível no Runner: {profile_name}.",
                           finding_status="not_evaluated",evidence=ev,target=target,executed=False,stderr=f"Template path missing: {template_path}")

        host,explicit_port,explicit_scheme=_host_from_target(target)
        candidate_ports=[explicit_port] if explicit_port else ports
        if not candidate_ports:
            candidate_ports=[443,80] if protocol=="http" else []

        open_ports=[]
        probe_evidence=[]
        for port in candidate_ports:
            probe=_tcp_probe(host,int(port),0.8)
            probe_evidence.append(probe)
            if probe.get("state")=="open":
                open_ports.append(int(port))

        if not open_ports and candidate_ports:
            preflight=_reachability_preflight(host,int(candidate_ports[0]),min(timeout_seconds,20))
            if not preflight.get("reachable"):
                ev={**base_evidence,"reason":"target_unreachable","service_preflight":{"candidate_ports":candidate_ports,"probes":probe_evidence,"reachability":preflight}}
                return _finish(started=started,status="target_unreachable",exit_code=2,
                    message=f"Target {target} sem evidência de reachability; {profile_name} não foi avaliado.",
                    finding_status="not_evaluated",evidence=ev,target=target,executed=False)
            ev={**base_evidence,"reason":"no_applicable_service","service_preflight":{"candidate_ports":candidate_ports,"probes":probe_evidence,"reachability":preflight}}
            return _finish(started=started,status="success",exit_code=0,
                message=f"{profile_name} não aplicável: nenhum serviço compatível foi encontrado em {target}.",
                finding_status="not_applicable",evidence=ev,target=target,executed=False)

        scan_targets=[]
        if explicit_scheme:
            scan_targets=[target]
        elif protocol=="http":
            for port in open_ports:
                scheme="https" if port in {443,8443,9443} else "http"
                default=(scheme=="http" and port==80) or (scheme=="https" and port==443)
                scan_targets.append(f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}")
        else:
            scan_targets=[f"{host}:{port}" for port in open_ports] or [target]

        target_file=Path(workdir)/"nuclei-targets.txt"
        target_file.write_text("\n".join(scan_targets)+"\n",encoding="utf-8")
        template_count=_count_templates(template_path)
        args=[binary,"-l",str(target_file),"-t",str(template_path),"-jsonl","-silent","-no-color","-duc"]
        severity=payload.get("severity")
        if severity:
            args += ["-severity",str(severity)]

        started_mono=time.monotonic()
        try:
            cp=subprocess.run(args,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=max(10,int(timeout_seconds)))
            rows=_parse_jsonl(cp.stdout)
            matches=[_normalize_match(x) for x in rows[:250]]
            sev=Counter(str(x.get("severity") or "unknown").lower() for x in matches)
            cves=sorted({cve for item in matches for cve in item.get("cves",[])})
            detected=bool(matches)
            status="success" if cp.returncode==0 else "failed"
            finding_status="detected" if detected else ("not_detected" if status=="success" else "error")

            if detected:
                if cves:
                    message=f"{profile_name}: {len(matches)} ocorrência(s) confirmada(s) em {target}; CVEs: {', '.join(cves[:8])}."
                else:
                    message=f"{profile_name}: {len(matches)} ocorrência(s) confirmada(s) em {target}."
            elif status=="success":
                message=f"{profile_name}: nenhuma condição foi confirmada no alvo {target}."
            else:
                message=f"{profile_name}: Nuclei falhou ao avaliar o alvo {target}."

            evidence={
                **base_evidence,
                "template_path":str(template_path),
                "templates_selected":template_count,
                "scan_targets":scan_targets,
                "service_preflight":{"candidate_ports":candidate_ports,"open_ports":open_ports,"probes":probe_evidence},
                "matches":matches,
                "match_count":len(matches),
                "severity_counts":dict(sev),
                "confirmed_cves":cves,
                "exit_code":cp.returncode,
            }
            result=_finish(started=started,status=status,exit_code=cp.returncode,message=message,
                finding_status=finding_status,evidence=evidence,target=target,executed=True,
                stdout=cp.stdout,stderr=cp.stderr,duration=round(time.monotonic()-started_mono,3))
            Path(workdir,"nuclei.json").write_text(json.dumps(result.metadata,indent=2,ensure_ascii=False),encoding="utf-8")
            return result
        except subprocess.TimeoutExpired as exc:
            ev={**base_evidence,"reason":"timeout","template_path":str(template_path),"templates_selected":template_count,
                "scan_targets":scan_targets,"service_preflight":{"candidate_ports":candidate_ports,"open_ports":open_ports,"probes":probe_evidence}}
            return _finish(started=started,status="timeout",exit_code=124,message=f"{profile_name}: timeout ao avaliar {target}.",
                finding_status="error",evidence=ev,target=target,executed=True,
                stdout=exc.stdout or "",stderr=exc.stderr or "")
