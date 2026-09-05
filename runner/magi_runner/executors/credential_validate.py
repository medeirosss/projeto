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

def _winrm_validate(target:str, credential:dict[str,Any], timeout:int)->tuple[bool,str|None,str,int,str]:
    """Validate WinRM using the same transport contract as MAGI-ATK-END-101."""
    user=str(credential.get('username') or '').strip()
    domain=str(credential.get('domain') or '').strip()
    secret=str(credential.get('secret') or '')
    identity=f"{domain}\\{user}" if domain and '\\' not in user and '@' not in user else user
    env=os.environ.copy()
    env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret})
    script=r'''$ErrorActionPreference='Stop'
$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force
$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s)
$trustedState=$null
$trustedChanged=$false
$stage='trustedhosts_snapshot'

function Get-MagiTrustedState {
  $wsmanPath='WSMan:\localhost\Client\TrustedHosts'
  try {
    if(Test-Path $wsmanPath){
      return [pscustomobject]@{method='wsman_provider';value=((Get-Item $wsmanPath -ErrorAction Stop).Value -as [string]);existed=$true}
    }
  } catch {}
  $regPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client'
  $prop=$null
  try { $prop=Get-ItemProperty -Path $regPath -Name 'trusted_hosts' -ErrorAction Stop } catch {}
  if($null -ne $prop){ return [pscustomobject]@{method='registry';value=($prop.trusted_hosts -as [string]);existed=$true} }
  return [pscustomobject]@{method='registry';value='';existed=$false}
}
function Set-MagiTrustedValue([object]$state,[string]$value) {
  if($state.method -eq 'wsman_provider'){Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value $value -Force -ErrorAction Stop;return}
  $regPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client'
  if(-not(Test-Path $regPath)){New-Item -Path $regPath -Force|Out-Null}
  New-ItemProperty -Path $regPath -Name 'trusted_hosts' -PropertyType String -Value $value -Force|Out-Null
}
function Restore-MagiTrustedValue([object]$state) {
  if($state.method -eq 'wsman_provider'){Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value ($state.value -as [string]) -Force -ErrorAction Stop;return}
  $regPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client'
  if($state.existed){
    if(-not(Test-Path $regPath)){New-Item -Path $regPath -Force|Out-Null}
    New-ItemProperty -Path $regPath -Name 'trusted_hosts' -PropertyType String -Value ($state.value -as [string]) -Force|Out-Null
  } else {Remove-ItemProperty -Path $regPath -Name 'trusted_hosts' -ErrorAction SilentlyContinue}
}
try {
  $trustedState=Get-MagiTrustedState
  $items=@()
  if($trustedState.value){$items=@($trustedState.value -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})}
  if(-not (($items -contains '*') -or ($items -contains $env:MAGI_TARGET))){
    $stage='trustedhosts_update'
    $newItems=@($items + $env:MAGI_TARGET | Select-Object -Unique)
    Set-MagiTrustedValue $trustedState ($newItems -join ',')
    $trustedChanged=$true
  }
  $stage='winrm_negotiate'
  $hostResult=Invoke-Command -ComputerName $env:MAGI_TARGET -Authentication Negotiate -Credential $c -ScriptBlock { hostname } -ErrorAction Stop
  $hostResult | Select-Object -Last 1
}
catch {
  [Console]::Error.WriteLine(("MAGI_WINRM_STAGE="+$stage+"; "+$_.Exception.Message))
  exit 11
}
finally {
  if($trustedChanged -and $null -ne $trustedState){
    try {Restore-MagiTrustedValue $trustedState}
    catch {[Console]::Error.WriteLine(("MAGI_WINRM_RESTORE_FAILED; "+$_.Exception.Message))}
  }
}'''
    try:
        p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],
            capture_output=True,text=True,timeout=max(8,timeout),env=env,shell=False)
        host=(p.stdout or '').strip().splitlines()[-1].strip() if (p.stdout or '').strip() else None
        ok=p.returncode==0 and bool(host)
        error='' if ok else (p.stderr or p.stdout or f'exit {p.returncode}')[-1600:]
        return ok,host,'winrm',1,error
    except subprocess.TimeoutExpired:
        return False,None,'winrm',1,'MAGI_WINRM_STAGE=timeout; WinRM validation timed out.'
    except Exception as exc:
        return False,None,'winrm',1,str(exc)[-1600:]

def _smb_validate(target:str, credential:dict[str,Any], timeout:int)->tuple[bool,str|None,str,int,str]:
    user=str(credential.get('username') or '').strip(); domain=str(credential.get('domain') or '').strip(); secret=str(credential.get('secret') or '')
    identity=f"{domain}\\{user}" if domain and '\\' not in user and '@' not in user else user
    env=os.environ.copy(); env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret})
    script=r'''$ErrorActionPreference='Stop';$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force;$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s);$n='MAGI'+([guid]::NewGuid().ToString('N').Substring(0,8));New-PSDrive -Name $n -PSProvider FileSystem -Root ("\\\\"+$env:MAGI_TARGET+"\\IPC$") -Credential $c -ErrorAction Stop|Out-Null;Remove-PSDrive -Name $n -Force;Write-Output $env:MAGI_TARGET'''
    try:
        p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],capture_output=True,text=True,timeout=max(8,timeout),env=env,shell=False)
        ok=p.returncode==0; return ok,(target if ok else None),'smb',1,'' if ok else (p.stderr or p.stdout or f'exit {p.returncode}')[-1600:]
    except Exception as exc: return False,None,'smb',1,str(exc)[-1600:]



def _create_benign_evidence(target:str, credential:dict[str,Any], protocol:str, payload:dict[str,Any], timeout:int)->dict[str,Any]:
    requested=bool(payload.get('create_benign_evidence'))
    if not requested:
        return {'evidence_requested':False,'evidence_created':False,'evidence_verified':False,'evidence_path':None,'evidence_error':None}

    campaign_context=payload.get('campaign_context') or {}
    campaign_uuid=str(campaign_context.get('campaign_uuid') or '')
    user=str(credential.get('username') or '').strip()
    domain=str(credential.get('domain') or '').strip()
    secret=str(credential.get('secret') or '')
    identity=f"{domain}\\{user}" if domain and '\\' not in user and '@' not in user else user
    content=f"MAGI esteve aqui\\nCampaign: {campaign_uuid}\\nTarget: {target}\\nProtocol: {protocol}\\n"

    if protocol=='winrm':
        evidence_path=str(payload.get('evidence_path') or r'C:\MAGI\MAGI_EVIDENCE.txt')
        env=os.environ.copy()
        env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret,'MAGI_EVIDENCE_PATH':evidence_path,'MAGI_EVIDENCE_CONTENT':content})
        script=r'''$ErrorActionPreference='Stop'
$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force
$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s)
$old=(Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
$changed=$false
try{
  $items=@();if($old){$items=@($old -split ','|ForEach-Object{$_.Trim()}|Where-Object{$_})}
  if(-not (($items -contains '*') -or ($items -contains $env:MAGI_TARGET))){
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((@($items+$env:MAGI_TARGET|Select-Object -Unique)) -join ',') -Force -ErrorAction Stop
    $changed=$true
  }
  $ok=Invoke-Command -ComputerName $env:MAGI_TARGET -Authentication Negotiate -Credential $c -ArgumentList $env:MAGI_EVIDENCE_PATH,$env:MAGI_EVIDENCE_CONTENT -ScriptBlock {
    param($path,$content)
    $dir=Split-Path $path -Parent
    New-Item -ItemType Directory -Path $dir -Force|Out-Null
    Set-Content -Path $path -Value $content -Encoding UTF8
    Test-Path $path
  } -ErrorAction Stop
  if($ok){Write-Output 'VERIFIED'}
}
finally{
  if($changed){try{Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($old -as [string]) -Force -ErrorAction SilentlyContinue}catch{}}
}'''
        try:
            proc=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],
                capture_output=True,text=True,timeout=max(8,timeout),env=env,shell=False)
            ok=proc.returncode==0 and 'VERIFIED' in (proc.stdout or '')
            return {'evidence_requested':True,'evidence_created':ok,'evidence_verified':ok,'evidence_path':evidence_path if ok else None,
                    'evidence_error':None if ok else (proc.stderr or proc.stdout or f'exit {proc.returncode}')[-1600:]}
        except Exception as exc:
            return {'evidence_requested':True,'evidence_created':False,'evidence_verified':False,'evidence_path':None,'evidence_error':str(exc)[-1600:]}

    if protocol=='smb':
        env=os.environ.copy()
        env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret,'MAGI_EVIDENCE_CONTENT':content})
        script=r'''$ErrorActionPreference='Stop'
$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force
$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s)
$n='MAGI'+([guid]::NewGuid().ToString('N').Substring(0,8))
try{
  New-PSDrive -Name $n -PSProvider FileSystem -Root ("\\"+$env:MAGI_TARGET+"\C$") -Credential $c -ErrorAction Stop|Out-Null
  $dir="${n}:\MAGI";New-Item -ItemType Directory -Path $dir -Force|Out-Null
  $file="${dir}\MAGI_EVIDENCE.txt";Set-Content -Path $file -Value $env:MAGI_EVIDENCE_CONTENT -Encoding UTF8
  if(Test-Path $file){Write-Output 'VERIFIED'}
}finally{Remove-PSDrive -Name $n -Force -ErrorAction SilentlyContinue}'''
        try:
            proc=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],
                capture_output=True,text=True,timeout=max(8,timeout),env=env,shell=False)
            ok=proc.returncode==0 and 'VERIFIED' in (proc.stdout or '')
            return {'evidence_requested':True,'evidence_created':ok,'evidence_verified':ok,'evidence_path':r'C:\MAGI\MAGI_EVIDENCE.txt' if ok else None,
                    'evidence_error':None if ok else (proc.stderr or proc.stdout or f'exit {proc.returncode}')[-1600:]}
        except Exception as exc:
            return {'evidence_requested':True,'evidence_created':False,'evidence_verified':False,'evidence_path':None,'evidence_error':str(exc)[-1600:]}

    return {'evidence_requested':True,'evidence_created':False,'evidence_verified':False,'evidence_path':None,'evidence_error':f'Evidence not implemented for protocol {protocol}.'}


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


def _failure_status(protocol: str, error: str, attempts: int) -> str:
    msg=(error or '').lower()
    if protocol=='ssh' and attempts==0 and ('paramiko' in msg or 'dependência' in msg or 'dependency' in msg):
        return 'runner_dependency_missing'
    transport_tokens=(
        'servernottrusted','trustedhosts','psremotingtransportexception','network path was not found',
        'caminho da rede não foi encontrado','domínio não está disponível','dominio nao esta disponivel',
        'no route to host','connection timed out','timed out','connection refused','name or service not known',
        'could not resolve hostname','actively refused','host is down','unreachable'
    )
    auth_tokens=(
        'access is denied','acesso negado','logon failure','falha de logon','authentication failed',
        'permission denied','user name or password is incorrect','username or password is incorrect',
        'the specified network password is not correct','account restriction'
    )
    if 'magi_winrm_stage=trustedhosts_' in msg or 'magi_winrm_restore_failed' in msg:
        return 'trustedhosts_failed'
    if 'magi_winrm_stage=timeout' in msg or 'timed out' in msg or 'timeout' in msg:
        return 'timeout'
    service_tokens=('winrm cannot complete the operation','winrm service','ws-management service','wsmanfault')
    if any(t in msg for t in auth_tokens):
        return 'authentication_failed'
    if any(t in msg for t in service_tokens):
        return 'service_unavailable'
    if any(t in msg for t in transport_tokens):
        return 'transport_failed'
    return 'access_not_confirmed'


class CredentialValidateExecutor:
    name='credential_validate'
    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc); payload=job.get('payload') or {}; target=str(payload.get('target') or job.get('target') or '').strip()
        cred=payload.get('credential') or {}; ctype=str(cred.get('type') or payload.get('credential_type') or '').lower()
        if not target or not cred.get('secret'): raise ValueError('Job de credencial sem target ou segredo transitório.')
        forced=str(payload.get('protocol') or '').lower()
        if forced=='smb': ok,hostname,protocol,attempts,error=_smb_validate(target,cred,timeout_seconds)
        elif forced=='winrm': ok,hostname,protocol,attempts,error=_winrm_validate(target,cred,timeout_seconds)
        elif ctype in {'windows','wmi','winrm'}: ok,hostname,protocol,attempts,error=_windows_validate(target,cred,timeout_seconds)
        elif ctype in {'ssh','linux'}: ok,hostname,protocol,attempts,error=_ssh_validate(target,cred,timeout_seconds)
        elif ctype in {'snmp','snmp_v2c','snmpv2c'}: ok,hostname,protocol,attempts,error=_snmp_validate(target,cred,timeout_seconds)
        else: ok,hostname,protocol,attempts,error=False,None,ctype,0,f'Tipo de credencial não suportado nesta versão: {ctype}'
        finished=datetime.now(timezone.utc)
        relation='discovery' if protocol=='snmp_v2c' else 'access'
        if ok:
            finding_status='discovery_confirmed' if relation=='discovery' else 'access_confirmed'
        elif relation=='discovery':
            finding_status='discovery_not_confirmed'
        else:
            finding_status=_failure_status(protocol,error,attempts)
        executed = finding_status != 'runner_dependency_missing'
        evidence=_create_benign_evidence(target,cred,protocol,payload,timeout_seconds) if ok and relation=='access' else {
            'evidence_requested':bool(payload.get('create_benign_evidence')),
            'evidence_created':False,'evidence_verified':False,'evidence_path':None,'evidence_error':None
        }
        metadata={'target':target,'credential_id':payload.get('credential_id'),'credential_name':cred.get('name'),'credential_type':ctype,'authenticated':ok,
                  'hostname':hostname,'protocol':protocol,'attempts_used':min(2,attempts),'max_attempts':2,'message':None if ok else error,
                  'campaign_context':payload.get('campaign_context') or {},'relation_type':relation,'executed_real_test':executed,
                  'execution_scope':'campaign_remote','attack_result':finding_status,'confirmation_status':finding_status,
                  'failure_class':None if ok else finding_status,
                  **evidence,
                  'finding':{'status':finding_status,'detected':ok,'message':(f'{protocol} confirmado em {target}.' if ok else f'{protocol} não confirmado em {target}: {error}')}}
        Path(workdir,'credential_validation.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False),encoding='utf-8')
        runner_error=finding_status=='runner_dependency_missing'
        return ExecutionResult(status='success' if ok else ('error' if runner_error else 'failed'),exit_code=0 if ok else (None if runner_error else 1),stdout=hostname or '',stderr='' if ok else error,
            started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata=metadata)
