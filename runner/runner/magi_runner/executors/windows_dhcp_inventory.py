from __future__ import annotations
import base64, json, re, shutil, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from .base import ExecutionResult
from .process import run_subprocess

def _decode_powershell_stream(value: str) -> tuple[str, list[str]]:
    """Remove PowerShell CLIXML envelopes while preserving their diagnostic text."""
    value = value or ''
    messages = []
    pattern = re.compile(r'(?m)^#< CLIXML\s*\r?\n')
    match = pattern.search(value)
    if not match:
        return value.strip(), messages
    prefix = value[:match.start()].strip()
    xml_text = value[match.end():].strip()
    try:
        root = ET.fromstring(xml_text)
        for element in root.iter():
            if element.tag.rsplit('}', 1)[-1] in ('S', 'ToString') and element.text:
                decoded = re.sub(r'_x([0-9a-fA-F]{4})_', lambda m: chr(int(m.group(1), 16)), element.text)
                if decoded.strip():
                    messages.append(decoded.strip())
    except ET.ParseError:
        messages.append(xml_text[:2000])
    return prefix, messages


def _extract_json(value: str):
    """Accept a JSON payload with benign PowerShell stream chatter around it."""
    decoder = json.JSONDecoder()
    for line in (value or '').splitlines():
        candidate = line.strip().lstrip('\ufeff')
        if not candidate or candidate.startswith('#< CLIXML'):
            continue
        if candidate[0] not in '{[':
            continue
        try:
            result, end = decoder.raw_decode(candidate)
            if not candidate[end:].strip():
                return result
        except json.JSONDecodeError:
            continue
    raise ValueError('No valid DHCP JSON payload found in PowerShell stdout')


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
$sb={
  $warnings=@(); $leases=@(); $scopes=@()
  $moduleErrors=@()
  # The DHCP migration localization resource can be installed only in en-US.
  # Check both supported locations on the remote server and scope the culture
  # override to module import only; never copy or modify Windows module files.
  $moduleRoot=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Modules\DhcpServer'
  $ptFile=Join-Path $moduleRoot 'pt-BR\DhcpServerMigration.psd1'
  $enFile=Join-Path $moduleRoot 'en-US\DhcpServerMigration.psd1'
  $previousCulture=[System.Threading.Thread]::CurrentThread.CurrentUICulture
  $fallbackCulture=$false
  try {
    if((-not (Test-Path -LiteralPath $ptFile)) -and (Test-Path -LiteralPath $enFile)) {
      [System.Threading.Thread]::CurrentThread.CurrentUICulture=[System.Globalization.CultureInfo]::GetCultureInfo('en-US')
      $fallbackCulture=$true
    }
    Import-Module DhcpServer -ErrorAction SilentlyContinue -ErrorVariable +moduleErrors
  }
  finally {
    [System.Threading.Thread]::CurrentThread.CurrentUICulture=$previousCulture
  }
  if($fallbackCulture){$warnings += 'DHCP localization fallback: en-US resource used because pt-BR resource is missing.'}
  foreach($e in $moduleErrors){$warnings += [string]$e}
  if(-not (Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)){ throw 'DHCP_MODULE_UNAVAILABLE: Get-DhcpServerv4Scope is not available on the DHCP server.' }
  Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object {
    $scope=$_; $sid=$scope.ScopeId.IPAddressToString
    $scopeLeases=@(Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction Stop)
    $active=@($scopeLeases | Where-Object { [string]$_.AddressState -match '^Active' })
    $stats=$null
    try{$stats=Get-DhcpServerv4ScopeStatistics -ScopeId $scope.ScopeId -ErrorAction Stop}catch{$warnings += ('Scope statistics warning: '+[string]$_)}
    $scopes += [pscustomobject]@{scope_id=$sid;name=$scope.Name;state=[string]$scope.State;active_leases=$active.Count;addresses_in_use=if($stats){[int]$stats.AddressesInUse}else{$active.Count};addresses_free=if($stats){[int]$stats.AddressesFree}else{$null};percentage_in_use=if($stats){[double]$stats.PercentageInUse}else{$null}}
    $scopeLeases | ForEach-Object { $leases += [pscustomobject]@{scope_id=$sid;ip_address=$_.IPAddress.IPAddressToString;hostname=$_.HostName;client_id=$_.ClientId;address_state=[string]$_.AddressState;lease_expiry=if($_.LeaseExpiryTime){$_.LeaseExpiryTime.ToString('o')}else{$null}} }
  }
  [pscustomobject]@{scopes=$scopes;leases=$leases;warnings=$warnings} | ConvertTo-Json -Depth 6 -Compress
}
try {
  $oldTrusted=(Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
  $items=@(); if($oldTrusted){$items=@($oldTrusted -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})}
  if(-not (($items -contains '*') -or ($items -contains $server))){
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((@($items+$server | Select-Object -Unique)) -join ',') -Force -ErrorAction Stop
    $trustedChanged=$true
  }
  $result=Invoke-Command -ComputerName $server -Authentication Negotiate -Credential $cred -ScriptBlock $sb -ErrorAction Stop
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
        warnings=[]
        clean_stdout, stdout_diagnostics = _decode_powershell_stream(r.stdout or '')
        clean_stderr, stderr_diagnostics = _decode_powershell_stream(r.stderr or '')
        diagnostics = stdout_diagnostics + stderr_diagnostics
        r.stderr = '\n'.join(x for x in [clean_stderr, *diagnostics] if x).strip()
        if r.status=='success':
            try:
                raw=_extract_json(clean_stdout)
            except (ValueError, TypeError) as exc:
                r.status='error'
                r.stderr=((r.stderr or '') + ('\n' if r.stderr else '') + f'Windows DHCP returned invalid JSON: {exc}').strip()
                raw={}
            if isinstance(raw,dict):
                scopes=raw.get('scopes') or []
                leases=raw.get('leases') or []
                warnings=raw.get('warnings') or []
                if not isinstance(scopes,list) or not isinstance(leases,list) or not isinstance(warnings,list):
                    r.status='error'
                    r.stderr=(r.stderr+'\nInvalid DHCP payload collection types').strip()
                    scopes=[]; leases=[]; warnings=[]
            elif isinstance(raw,list):
                leases=raw
        # A localized DhcpServerMigration.psd1 import error is non-fatal when
        # the inventory cmdlets succeeded and valid JSON was returned.
        nonfatal = [x for x in diagnostics if 'DhcpServerMigration.psd1' in x]
        if r.status=='success' and nonfatal:
            warnings.extend(nonfatal)
            r.stderr='\n'.join(x for x in [clean_stderr, *[d for d in diagnostics if d not in nonfatal]] if x).strip()
        active_leases=[x for x in leases if isinstance(x,dict) and str(x.get('address_state') or '').lower().startswith('active')]
        r.metadata={**(r.metadata or {}),'provider':'windows_dhcp','dhcp_server':server,'scope_count':len(scopes),'scopes':scopes,'lease_count':len(leases),'active_lease_count':len(active_leases),'leases':leases,'warnings':warnings,'warning_count':len(warnings)}
        r.stdout=json.dumps({'provider':'windows_dhcp','dhcp_server':server,'scope_count':len(scopes),'lease_count':len(leases),'active_lease_count':len(active_leases),'warning_count':len(warnings)},ensure_ascii=False)
        return r
