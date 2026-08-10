from __future__ import annotations

import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import ExecutionResult


def _windows_validate(target:str, credential:dict[str,Any], timeout:int)->tuple[bool,str|None,str,int,str]:
    user=str(credential.get('username') or '').strip()
    domain=str(credential.get('domain') or '').strip()
    secret=str(credential.get('secret') or '')
    identity=f"{domain}\\{user}" if domain and '\\' not in user and '@' not in user else user
    env=os.environ.copy(); env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret})
    # Attempt 1 = WMI/CIM over DCOM. Attempt 2 = WinRM PowerShell remoting.
    scripts=[
        r'''$ErrorActionPreference='Stop';$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force;$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s);$o=New-CimSessionOption -Protocol Dcom;$cs=New-CimSession -ComputerName $env:MAGI_TARGET -Credential $c -SessionOption $o;$n=(Get-CimInstance Win32_ComputerSystem -CimSession $cs).Name;Remove-CimSession $cs;Write-Output $n''',
        r'''$ErrorActionPreference='Stop';$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force;$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s);Invoke-Command -ComputerName $env:MAGI_TARGET -Credential $c -ScriptBlock { hostname } -ErrorAction Stop'''
    ]
    errors=[]
    for idx,script in enumerate(scripts,1):
        try:
            p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],capture_output=True,text=True,timeout=max(8,timeout//2),env=env,shell=False)
            host=(p.stdout or '').strip().splitlines()[-1].strip() if (p.stdout or '').strip() else None
            if p.returncode==0 and host:
                return True,host,'wmi_dcom' if idx==1 else 'winrm',idx,''
            errors.append((p.stderr or p.stdout or f'exit {p.returncode}').strip())
        except Exception as exc:
            errors.append(str(exc))
    return False,None,'windows',2,' | '.join(e for e in errors if e)[-1600:]


def _ssh_validate(target:str, credential:dict[str,Any], timeout:int)->tuple[bool,str|None,str,int,str]:
    try:
        import paramiko
    except Exception:
        return False,None,'ssh',0,'Dependência paramiko não encontrada no Runner.'
    user=str(credential.get('username') or '').strip(); secret=str(credential.get('secret') or '')
    port=int((credential.get('metadata') or {}).get('port') or 22); last=''
    for attempt in range(1,3):
        client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target,port=port,username=user,password=secret,timeout=min(12,timeout),banner_timeout=min(12,timeout),auth_timeout=min(12,timeout),look_for_keys=False,allow_agent=False)
            _,stdout,stderr=client.exec_command('hostname',timeout=min(12,timeout)); host=stdout.read().decode(errors='replace').strip().splitlines()[0] if stdout else ''
            if host: return True,host,'ssh',attempt,''
            last=(stderr.read().decode(errors='replace') if stderr else '') or 'hostname sem retorno'
        except Exception as exc: last=str(exc)
        finally:
            try: client.close()
            except Exception: pass
    return False,None,'ssh',2,last[-1600:]


def _ber_len(n:int)->bytes:
    return bytes([n]) if n<128 else bytes([0x81,n])

def _ber(tag:int,content:bytes)->bytes: return bytes([tag])+_ber_len(len(content))+content

def _ber_int(n:int)->bytes:
    raw=n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
    if raw[0]&0x80: raw=b'\x00'+raw
    return _ber(0x02,raw)

def _ber_oid(parts:list[int])->bytes:
    first=bytes([40*parts[0]+parts[1]]); out=bytearray(first)
    for n in parts[2:]:
        stack=[n&0x7f]; n>>=7
        while n: stack.append((n&0x7f)|0x80); n>>=7
        out.extend(reversed(stack))
    return _ber(0x06,bytes(out))

def _snmp_v2_hostname(target:str,community:str,timeout:int)->tuple[bool,str|None,str]:
    req_id=0x4D414749
    oid=[1,3,6,1,2,1,1,5,0]
    vb=_ber(0x30,_ber_oid(oid)+_ber(0x05,b'')); vbl=_ber(0x30,vb)
    pdu=_ber(0xA0,_ber_int(req_id)+_ber_int(0)+_ber_int(0)+vbl)
    msg=_ber(0x30,_ber_int(1)+_ber(0x04,community.encode())+pdu)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(min(5,max(1,timeout)))
    try:
        s.sendto(msg,(target,161)); data,_=s.recvfrom(65535)
        # sysName string is typically the final OCTET STRING. Parse generic TLV and select printable string.
        strings=[]
        def walk(buf:bytes,start=0,end=None):
            end=len(buf) if end is None else end; i=start
            while i+2<=end:
                tag=buf[i]; i+=1; l=buf[i]; i+=1
                if l&0x80:
                    c=l&0x7f
                    if i+c>end: return
                    l=int.from_bytes(buf[i:i+c],'big'); i+=c
                if i+l>end: return
                val=buf[i:i+l]
                if tag==0x04:
                    try:
                        txt=val.decode('utf-8').strip()
                        if txt and txt!=community and all(ch.isprintable() for ch in txt): strings.append(txt)
                    except Exception: pass
                if tag in (0x30,0xA0,0xA2): walk(val,0,len(val))
                i+=l
        walk(data)
        host=strings[-1] if strings else None
        return bool(host),host,'' if host else 'Resposta SNMP recebida sem sysName legível.'
    except Exception as exc: return False,None,str(exc)
    finally: s.close()


def _snmp_validate(target:str,credential:dict[str,Any],timeout:int)->tuple[bool,str|None,str,int,str]:
    community=str(credential.get('secret') or '')
    last=''
    for attempt in range(1,3):
        ok,host,last=_snmp_v2_hostname(target,community,timeout)
        if ok: return True,host,'snmp_v2c',attempt,''
    return False,None,'snmp_v2c',2,last[-1600:]


class CredentialValidateExecutor:
    name='credential_validate'
    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc); payload=job.get('payload') or {}; target=str(payload.get('target') or job.get('target') or '').strip()
        cred=payload.get('credential') or {}; ctype=str(cred.get('type') or payload.get('credential_type') or '').lower()
        if not target or not cred.get('secret'): raise ValueError('Job de credencial sem target ou segredo transitório.')
        if ctype in {'windows','wmi','winrm'}: ok,hostname,protocol,attempts,error=_windows_validate(target,cred,timeout_seconds)
        elif ctype in {'ssh','linux'}: ok,hostname,protocol,attempts,error=_ssh_validate(target,cred,timeout_seconds)
        elif ctype in {'snmp','snmp_v2c','snmpv2c'}: ok,hostname,protocol,attempts,error=_snmp_validate(target,cred,timeout_seconds)
        else: ok,hostname,protocol,attempts,error=False,None,ctype,0,f'Tipo de credencial não suportado nesta versão: {ctype}'
        finished=datetime.now(timezone.utc)
        metadata={'target':target,'credential_id':payload.get('credential_id'),'credential_name':cred.get('name'),'credential_type':ctype,'authenticated':ok,
                  'hostname':hostname,'protocol':protocol,'attempts_used':min(2,attempts),'max_attempts':2,'message':None if ok else error}
        Path(workdir,'credential_validation.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False),encoding='utf-8')
        return ExecutionResult(status='success' if ok else 'failed',exit_code=0 if ok else 1,stdout=hostname or '',stderr='' if ok else error,
            started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata=metadata)
