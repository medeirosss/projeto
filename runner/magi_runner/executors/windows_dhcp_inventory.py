from __future__ import annotations
import base64, json, re, shutil
from datetime import datetime, timezone
from .base import ExecutionResult
from .process import run_subprocess

_HOST=re.compile(r'^[A-Za-z0-9._-]{1,255}$')
class WindowsDhcpInventoryExecutor:
    name='windows_dhcp_inventory'
    def run(self, job:dict, workdir:str, timeout_seconds:int)->ExecutionResult:
        started=datetime.now(timezone.utc)
        payload=job.get('payload') or {}; server=str(payload.get('dhcp_server') or job.get('target') or '').strip()
        if not _HOST.fullmatch(server): raise ValueError('Invalid Windows DHCP server')
        cred=payload.get('credential') or {}; user=str(cred.get('username') or ''); domain=str(cred.get('domain') or ''); secret=str(cred.get('secret') or '')
        if not user or not secret: raise ValueError('Windows DHCP inventory requires credential')
        principal=(domain+'\\'+user) if domain else user
        # Fixed read-only script. Operator input is base64-decoded inside PowerShell, never interpolated as code.
        enc=lambda x: base64.b64encode(x.encode('utf-8')).decode('ascii')
        script=r'''$ErrorActionPreference='Stop'
$server=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SERVER__'))
$user=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__USER__'))
$pass=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PASS__'))
$sec=ConvertTo-SecureString $pass -AsPlainText -Force
$cred=New-Object System.Management.Automation.PSCredential($user,$sec)
$sb={ param($srv) Import-Module DhcpServer -ErrorAction Stop; $out=@(); Get-DhcpServerv4Scope -ComputerName $srv | ForEach-Object { $sid=$_.ScopeId.IPAddressToString; Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $_.ScopeId | ForEach-Object { $out += [pscustomobject]@{scope_id=$sid;ip_address=$_.IPAddress.IPAddressToString;hostname=$_.HostName;client_id=$_.ClientId;address_state=[string]$_.AddressState;lease_expiry=if($_.LeaseExpiryTime){$_.LeaseExpiryTime.ToString('o')}else{$null}} } }; $out | ConvertTo-Json -Depth 4 -Compress }
$result=Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock $sb -ArgumentList $server
$result
'''.replace('__SERVER__',enc(server)).replace('__USER__',enc(principal)).replace('__PASS__',enc(secret))
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        exe=shutil.which('powershell.exe') or shutil.which('powershell') or shutil.which('pwsh')
        if not exe: raise RuntimeError('PowerShell executable not found')
        r=run_subprocess([exe,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',encoded],workdir,min(timeout_seconds or 90,120))
        leases=[]
        if r.status=='success' and (r.stdout or '').strip():
            raw=json.loads((r.stdout or '').strip()); leases=raw if isinstance(raw,list) else ([raw] if isinstance(raw,dict) else [])
        r.metadata={**(r.metadata or {}),'provider':'windows_dhcp','dhcp_server':server,'lease_count':len(leases),'leases':leases}
        r.stdout=json.dumps({'provider':'windows_dhcp','dhcp_server':server,'lease_count':len(leases)},ensure_ascii=False)
        return r
