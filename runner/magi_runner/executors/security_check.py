from __future__ import annotations
import json,socket,time
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
from .base import ExecutionResult

class SecurityCheckExecutor:
    name='security_check'
    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc); payload=job.get('payload') or {}; target=str(payload.get('target') or job.get('target') or '').strip(); detection=payload.get('detection') or {}
        if not target: raise ValueError('security_check requer target')
        if detection.get('type')!='tcp_port': raise ValueError(f"Tipo de check não suportado: {detection.get('type')}")
        port=int(detection.get('port')); connect_timeout=min(5,max(1,timeout_seconds)); t0=time.monotonic(); opened=False; error=''
        try:
            with socket.create_connection((target,port),timeout=connect_timeout): opened=True
        except Exception as exc: error=str(exc)
        latency_ms=round((time.monotonic()-t0)*1000,2); finding_when=detection.get('finding_when','open'); detected=opened if finding_when=='open' else not opened
        state='open' if opened else 'closed_or_filtered'; message=f"TCP/{port} {state} em {target}."; finding={'detected':detected,'status':'detected' if detected else 'not_detected','message':message}
        evidence={'check_type':'tcp_port','target':target,'port':port,'state':state,'latency_ms':latency_ms,'error':error or None,'observed_from':'runner'}
        finished=datetime.now(timezone.utc); metadata={'task_key':payload.get('task_key'),'repository_key':payload.get('repository_key'),'finding':finding,'evidence':evidence,'message':message,'remediation':payload.get('remediation')}
        Path(workdir,'security_check.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False),encoding='utf-8')
        return ExecutionResult(status='success',exit_code=0,stdout=message,stderr='',started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata=metadata)
