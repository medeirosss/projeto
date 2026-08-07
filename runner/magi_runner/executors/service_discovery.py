from __future__ import annotations
import ipaddress
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .base import ExecutionResult
from .nmap_discovery import find_nmap


def _target(value:str)->str:
    addr=ipaddress.ip_address(value.strip())
    if addr.version!=4: raise ValueError('Somente IPv4 é suportado nesta versão.')
    return str(addr)


def _parse(xml_text:str)->list[dict[str,Any]]:
    root=ET.fromstring(xml_text); out=[]
    for host in root.findall('host'):
        ports=host.find('ports')
        if ports is None: continue
        for p in ports.findall('port'):
            state=p.find('state'); svc=p.find('service')
            if state is None or state.get('state')!='open': continue
            cpes=[]
            if svc is not None:
                cpes=[(c.text or '').strip() for c in svc.findall('cpe') if (c.text or '').strip()]
            out.append({
                'port':int(p.get('portid') or 0),
                'protocol':p.get('protocol') or 'tcp',
                'state':state.get('state') or 'open',
                'reason':state.get('reason'),
                'reason_ttl':state.get('reason_ttl'),
                'service_name':svc.get('name') if svc is not None else None,
                'product':svc.get('product') if svc is not None else None,
                'version':svc.get('version') if svc is not None else None,
                'extra_info':svc.get('extrainfo') if svc is not None else None,
                'os_type':svc.get('ostype') if svc is not None else None,
                'tunnel':svc.get('tunnel') if svc is not None else None,
                'method':svc.get('method') if svc is not None else None,
                'conf':svc.get('conf') if svc is not None else None,
                'service_fingerprint':svc.get('servicefp') if svc is not None else None,
                'cpe':cpes,
                'banner':' '.join(x for x in [svc.get('product') if svc is not None else None,svc.get('version') if svc is not None else None,svc.get('extrainfo') if svc is not None else None] if x) or None,
            })
    return out


class ServiceDiscoveryExecutor:
    name='service_discovery'
    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc); payload=job.get('payload') or {}; target=_target(str(payload.get('target') or job.get('target') or ''))
        nmap=find_nmap(payload.get('nmap_path'))
        if not nmap: raise RuntimeError('Nmap não encontrado. Instale o Nmap no Windows do Runner e reinicie o Runner.')
        args=[nmap,'-Pn','-n','-sV','--top-ports','1000','--open','-T4','--max-retries','1','-oX','-',target]
        try:
            proc=subprocess.run(args,cwd=workdir,capture_output=True,text=True,timeout=timeout_seconds,shell=False)
            finished=datetime.now(timezone.utc); xml_text=proc.stdout or ''; services=_parse(xml_text) if proc.returncode==0 and xml_text.strip() else []
            Path(workdir,'service_discovery_command.txt').write_text(subprocess.list2cmdline(args),encoding='utf-8')
            Path(workdir,'service_discovery_stdout.txt').write_text(xml_text,encoding='utf-8')
            Path(workdir,'services.xml').write_text(xml_text,encoding='utf-8')
            Path(workdir,'services.json').write_text(json.dumps(services,indent=2,ensure_ascii=False),encoding='utf-8')
            return ExecutionResult(status='success' if proc.returncode==0 else 'failed',exit_code=proc.returncode,stdout=xml_text,stderr=proc.stderr or '',started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata={'provider':'runner','target':target,'services':services,'service_count':len(services),'raw_xml':xml_text,'nmap_path':nmap,'args':args,'profile':'top1000','version_intensity':'normal'})
        except subprocess.TimeoutExpired as exc:
            finished=datetime.now(timezone.utc)
            return ExecutionResult(status='timeout',exit_code=None,stdout=exc.stdout.decode(errors='replace') if isinstance(exc.stdout,bytes) else (exc.stdout or ''),stderr=exc.stderr.decode(errors='replace') if isinstance(exc.stderr,bytes) else (exc.stderr or ''),started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata={'provider':'runner','target':target,'services':[],'timeout':timeout_seconds,'nmap_path':nmap})
