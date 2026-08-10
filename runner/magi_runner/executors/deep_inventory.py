from __future__ import annotations
import json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .base import ExecutionResult


def _windows(target:str,cred:dict[str,Any],rules:list[dict],timeout:int):
    user=str(cred.get('username') or '').strip(); domain=str(cred.get('domain') or '').strip(); secret=str(cred.get('secret') or '')
    identity=f"{domain}\\{user}" if domain and '\\' not in user and '@' not in user else user
    env=os.environ.copy(); env.update({'MAGI_TARGET':target,'MAGI_USER':identity,'MAGI_SECRET':secret,'MAGI_RULES':json.dumps(rules,ensure_ascii=False)})
    script=r'''$ErrorActionPreference='Stop'
$s=ConvertTo-SecureString $env:MAGI_SECRET -AsPlainText -Force
$c=New-Object System.Management.Automation.PSCredential($env:MAGI_USER,$s)
$o=New-CimSessionOption -Protocol Dcom
$cs=New-CimSession -ComputerName $env:MAGI_TARGET -Credential $c -SessionOption $o
$computer=Get-CimInstance Win32_ComputerSystem -CimSession $cs
$os=Get-CimInstance Win32_OperatingSystem -CimSession $cs
$bios=Get-CimInstance Win32_BIOS -CimSession $cs
$cpu=Get-CimInstance Win32_Processor -CimSession $cs | Select-Object -First 1
$disks=Get-CimInstance Win32_DiskDrive -CimSession $cs | ForEach-Object {[ordered]@{device=$_.DeviceID;model=$_.Model;serial=($_.SerialNumber -as [string]);size=[int64]$_.Size;interface=$_.InterfaceType}}
$rules=@(); try {$rules=$env:MAGI_RULES|ConvertFrom-Json}catch{}
$wanted=@{}; foreach($r in $rules){if($r.process_name){$wanted[$r.process_name.ToLowerInvariant()]=$r}}
$matches=@(); if($wanted.Count -gt 0){
  Get-CimInstance Win32_Process -CimSession $cs | ForEach-Object {
    $key=([string]$_.Name).ToLowerInvariant(); if($wanted.ContainsKey($key)){$r=$wanted[$key];$matches += [ordered]@{rule_id=[int]$r.id;process_name=[string]$_.Name;process_path=[string]$_.ExecutablePath;pid=[int]$_.ProcessId;sha256=$null;publisher=$null;signed=$null;category=[string]$r.category;severity=[string]$r.severity}}
  }
}
$result=[ordered]@{inventory=[ordered]@{hostname=[string]$computer.Name;os_name=[string]$os.Caption;os_version=[string]$os.Version;os_build=[string]$os.BuildNumber;domain_name=[string]$computer.Domain;manufacturer=[string]$computer.Manufacturer;model=[string]$computer.Model;serial_number=[string]$bios.SerialNumber;cpu_model=[string]$cpu.Name;cpu_cores=[int]$cpu.NumberOfCores;cpu_logical=[int]$cpu.NumberOfLogicalProcessors;memory_bytes=[int64]$computer.TotalPhysicalMemory;disks=@($disks);uptime_seconds=$null};process_matches=@($matches)}
Remove-CimSession $cs
$result|ConvertTo-Json -Depth 8 -Compress
'''
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],capture_output=True,text=True,timeout=timeout,env=env,shell=False)
    if p.returncode!=0: raise RuntimeError((p.stderr or p.stdout or f'exit {p.returncode}')[-3000:])
    lines=[x.strip() for x in (p.stdout or '').splitlines() if x.strip()]
    if not lines: raise RuntimeError('Deep Inventory Windows não retornou JSON.')
    return json.loads(lines[-1])


def _ssh(target:str,cred:dict[str,Any],rules:list[dict],timeout:int):
    try: import paramiko
    except Exception as exc: raise RuntimeError('Dependência paramiko não encontrada no Runner.') from exc
    user=str(cred.get('username') or '').strip(); secret=str(cred.get('secret') or ''); port=int((cred.get('metadata') or {}).get('port') or 22)
    cli=paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(target,port=port,username=user,password=secret,timeout=min(timeout,15),auth_timeout=min(timeout,15),look_for_keys=False,allow_agent=False)
        def cmd(c):
            _,o,e=cli.exec_command(c,timeout=min(timeout,20)); out=o.read().decode(errors='replace').strip(); err=e.read().decode(errors='replace').strip(); return out if out else err
        hostname=cmd('hostname'); os_name=cmd(". /etc/os-release 2>/dev/null; printf '%s' \"${PRETTY_NAME:-$(uname -s)}\"")
        os_version=cmd(". /etc/os-release 2>/dev/null; printf '%s' \"${VERSION_ID:-$(uname -r)}\"")
        cpu_model=cmd("lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,\"\",$2);print $2;exit}'")
        mem=cmd("awk '/MemTotal/{print $2*1024}' /proc/meminfo")
        disks=[]
        try:
            raw=cmd("lsblk -b -J -o NAME,MODEL,SERIAL,SIZE,TYPE 2>/dev/null"); data=json.loads(raw); disks=[{'device':x.get('name'),'model':x.get('model'),'serial':x.get('serial'),'size':x.get('size'),'interface':None} for x in data.get('blockdevices',[]) if x.get('type')=='disk']
        except Exception: pass
        procs=cmd('ps -eo pid=,comm=,args=')
        wanted={str(r.get('process_name') or '').lower():r for r in rules}; matches=[]
        for line in procs.splitlines():
            parts=line.strip().split(None,2)
            if len(parts)<2: continue
            pid,name=parts[0],parts[1]; key=os.path.basename(name).lower()
            if key in wanted:
                r=wanted[key]; matches.append({'rule_id':r.get('id'),'process_name':os.path.basename(name),'process_path':parts[2] if len(parts)>2 else None,'pid':int(pid),'sha256':None,'publisher':None,'signed':None,'category':r.get('category'),'severity':r.get('severity')})
        return {'inventory':{'hostname':hostname,'os_name':os_name,'os_version':os_version,'os_build':cmd('uname -r'),'domain_name':None,'manufacturer':None,'model':None,'serial_number':None,'cpu_model':cpu_model,'cpu_cores':None,'cpu_logical':None,'memory_bytes':int(float(mem)) if mem.replace('.','',1).isdigit() else None,'disks':disks,'uptime_seconds':None},'process_matches':matches}
    finally: cli.close()


class DeepInventoryExecutor:
    name='deep_inventory'
    def run(self,job:dict[str,Any],workdir:str,timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc); payload=job.get('payload') or {}; target=str(payload.get('target') or job.get('target') or '').strip(); cred=payload.get('credential') or {}; rules=payload.get('process_rules') or []
        if not target or not cred.get('secret'): raise ValueError('Job Deep Inventory sem target ou credencial transitória.')
        ctype=str(cred.get('type') or '').lower()
        if ctype in {'windows','wmi','winrm'}: data=_windows(target,cred,rules,timeout_seconds)
        elif ctype in {'ssh','linux'}: data=_ssh(target,cred,rules,timeout_seconds)
        else: raise ValueError(f'Deep Inventory ainda não implementado para credencial {ctype}.')
        finished=datetime.now(timezone.utc); metadata={'target':target,'credential_id':payload.get('credential_id'),'credential_type':ctype,'inventory':data.get('inventory') or {},'process_matches':data.get('process_matches') or []}
        Path(workdir,'deep_inventory.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False),encoding='utf-8')
        return ExecutionResult(status='success',exit_code=0,stdout='',stderr='',started_at=started.isoformat(),finished_at=finished.isoformat(),duration_seconds=(finished-started).total_seconds(),metadata=metadata)
