from __future__ import annotations

import os
from app.repositories import target_repository as target_repo
from app.repositories.runner_repository import create_runner_job, get_online_runner_with_capability
from app.services.nmap_provider import validate_target_spec, target_address_count, target_type, DiscoveryExecutionError
from app.services.settings_service import get_settings_data

class RunnerDiscoveryProvider:
    name = "runner"

    def enqueue(self, scan:dict, trigger_type:str="manual") -> dict:
        spec=validate_target_spec(scan["target_spec"])
        if target_type(spec)=="network" and target_address_count(spec)>256:
            raise ValueError("A versão 1.0 permite redes de até /24.")
        runner=get_online_runner_with_capability("nmap_discovery")
        if not runner:
            raise DiscoveryExecutionError("Nenhum Runner online com Nmap disponível. Instale o Nmap no Windows do Runner e aguarde o próximo heartbeat.")
        timeout=30 if target_address_count(spec)==1 else int(os.getenv("DISCOVERY_RUNNER_TIMEOUT_SECONDS","180"))
        dns_cfg=(get_settings_data().get("discovery", {}).get("dns", {}) or {})
        payload={"executor":"nmap_discovery","target":spec,"target_type":target_type(spec),"scan_uuid":scan.get("scan_uuid"),"provider":"runner","timeout_seconds":timeout,"dns":dns_cfg}
        job=create_runner_job(runner_id=runner["runner_id"],job_type="nmap_discovery",target=spec,payload=payload)
        run=target_repo.create_queued_discovery_run(spec,int(scan["id"]),trigger_type,target_address_count(spec),runner["runner_id"],int(job["id"]),"runner")
        return {"success":True,"queued":True,"status":"queued","run_uuid":run["run_uuid"],"runner_job_id":job["id"],"runner_id":runner["runner_id"],"discovered_count":0}
