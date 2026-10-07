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
$oldTrusted=$null;$trustedChanged=$false
$sb={ param($srv) Import-Module DhcpServer -ErrorAction Stop; $leases=@(); $scopes=@(); Get-DhcpServerv4Scope -ComputerName $srv | ForEach-Object { $scope=$_; $sid=$scope.ScopeId.IPAddressToString; $scopeLeases=@(Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $scope.ScopeId); $active=@($scopeLeases | Where-Object { [string]$_.AddressState -match '^Active' }); $stats=$null; try{$stats=Get-DhcpServerv4ScopeStatistics -ComputerName $srv -ScopeId $scope.ScopeId -ErrorAction Stop}catch{}; $scopes += [pscustomobject]@{scope_id=$sid;name=$scope.Name;state=[string]$scope.State;active_leases=$active.Count;addresses_in_use=if($stats){[int]$stats.AddressesInUse}else{$active.Count};addresses_free=if($stats){[int]$stats.AddressesFree}else{$null};percentage_in_use=if($stats){[double]$stats.PercentageInUse}else{$null}}; $scopeLeases | ForEach-Object { $leases += [pscustomobject]@{scope_id=$sid;ip_address=$_.IPAddress.IPAddressToString;hostname=$_.HostName;client_id=$_.ClientId;address_state=[string]$_.AddressState;lease_expiry=if($_.LeaseExpiryTime){$_.LeaseExpiryTime.ToString('o')}else{$null}} } }; [pscustomobject]@{scopes=$scopes;leases=$leases} | ConvertTo-Json -Depth 5 -Compress }
try {
  $oldTrusted=(Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
  $items=@(); if($oldTrusted){$items=@($oldTrusted -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})}
  if(-not (($items -contains '*') -or ($items -contains $server))){
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((@($items+$server | Select-Object -Unique)) -join ',') -Force -ErrorAction Stop
    $trustedChanged=$true
  }
  $result=Invoke-Command -ComputerName $server -Authentication Negotiate -Credential $cred -ScriptBlock $sb -ArgumentList $server -ErrorAction Stop
  $result
}
finally {
  if($trustedChanged){try{Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($oldTrusted -as [string]) -Force -ErrorAction SilentlyContinue}catch{}}
}
'''.replace('__SERVER__',enc(server)).replace('__USER__',enc(principal)).replace('__PASS__',enc(secret))
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        exe=shutil.which('powershell.exe') or shutil.which('powershell') or shutil.which('pwsh')
        if not exe: raise RuntimeError('PowerShell executable not found')
        r=run_subprocess([exe,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',encoded],workdir,min(timeout_seconds or 90,120))
        # Always initialize normalized collections. A failed PowerShell/WinRM call must
        # return the original execution failure, never crash while building metadata.
        scopes=[]
        leases=[]
        if r.status=='success' and (r.stdout or '').strip():
            try:
                raw=json.loads((r.stdout or '').strip())
            except (json.JSONDecodeError, TypeError) as exc:
                r.status='error'
                r.stderr=((r.stderr or '') + ('\n' if r.stderr else '') + f'Windows DHCP returned invalid JSON: {exc}').strip()
                raw={}
            if isinstance(raw,dict):
                scopes=raw.get('scopes') or []
                leases=raw.get('leases') or []
            elif isinstance(raw,list):
                leases=raw
        active_leases=[x for x in leases if str(x.get('address_state') or '').lower().startswith('active')]
        r.metadata={**(r.metadata or {}),'provider':'windows_dhcp','dhcp_server':server,'scope_count':len(scopes),'scopes':scopes,'lease_count':len(leases),'active_lease_count':len(active_leases),'leases':leases}
        r.stdout=json.dumps({'provider':'windows_dhcp','dhcp_server':server,'scope_count':len(scopes),'lease_count':len(leases),'active_lease_count':len(active_leases)},ensure_ascii=False)
        return r
