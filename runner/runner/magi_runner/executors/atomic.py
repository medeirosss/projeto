from __future__ import annotations

import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any

from .base import ExecutionResult

_PREVENTION_PATTERNS = (
    ("antimalware", r"virus|vírus|software possivelmente indesejado|potentially unwanted|malware"),
    ("security_block", r"blocked by|foi bloquead|security policy|antivirus|anti-virus|windows defender"),
)
_DEPENDENCY_PATTERNS = (
    r"is not recognized as an internal or external command",
    r"n[aã]o .* reconhecido como um comando interno",
    r"cannot find path",
    r"could not find.*externalpayload",
    r"prereq.*failed",
    r"prerequisite.*failed",
    r"failed to get prereq",
    r"failed to download",
    r"download.*failed",
)
_EXECUTION_ERROR_PATTERNS = (
    r"fullyqualifiederrorid",
    r"write-error",
    r"permissiondenied",
    r"unauthorizedaccessexception",
    r"methodinvocationexception",
    r"cannot find path",
    r"n[aã]o foi poss[ií]vel concluir a opera",
)
_ATOMIC_EXIT_RE = re.compile(r"Exit code:\s*(-?\d+)", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _result(*, started: datetime, status: str, exit_code: int | None, stdout: str = "", stderr: str = "", metadata: dict[str, Any] | None = None) -> ExecutionResult:
    finished = _now()
    return ExecutionResult(
        status=status,
        exit_code=exit_code,
        stdout=stdout or "",
        stderr=stderr or "",
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=(finished - started).total_seconds(),
        metadata=metadata or {},
    )


def _target_port(credential: dict[str, Any]) -> tuple[int, bool]:
    metadata = credential.get("metadata") if isinstance(credential.get("metadata"), dict) else {}
    use_https = bool(metadata.get("use_https", False))
    try:
        port = int(metadata.get("port") or (5986 if use_https else 5985))
    except Exception:
        port = 5986 if use_https else 5985
    return port, use_https


def _winrm_reachable(target: str, port: int, timeout: float = 4.0) -> tuple[bool, str | None]:
    try:
        socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except Exception as exc:
        return False, f"Falha ao resolver target: {exc}"
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True, None
    except Exception as exc:
        return False, str(exc)


def _identity(credential: dict[str, Any]) -> str:
    user = str(credential.get("username") or "").strip()
    domain = str(credential.get("domain") or "").strip()
    if domain and "\\" not in user and "@" not in user:
        return f"{domain}\\{user}"
    return user


def _execution_section(output: str) -> str:
    if "MAGI_EXECUTE_BEGIN" in output:
        output = output.split("MAGI_EXECUTE_BEGIN", 1)[1]
    if "MAGI_EXECUTE_END" in output:
        output = output.split("MAGI_EXECUTE_END", 1)[0]
    return output


def _atomic_exit_code(output: str) -> int | None:
    matches = _ATOMIC_EXIT_RE.findall(_execution_section(output))
    if not matches:
        return None
    try:
        return int(matches[-1])
    except Exception:
        return None


def _classify_remote_atomic(output: str, process_status: str, process_exit: int | None) -> tuple[str, list[str], int | None]:
    execution_output = _execution_section(output or "")
    lower = execution_output.lower()
    atomic_exit = _atomic_exit_code(output or "")

    signals: list[str] = []
    for label, pattern in _PREVENTION_PATTERNS:
        if re.search(pattern, execution_output, flags=re.IGNORECASE):
            signals.append(label)

    if signals:
        return "prevented", signals, atomic_exit

    if any(re.search(pattern, lower, flags=re.IGNORECASE) for pattern in _DEPENDENCY_PATTERNS):
        return "dependency_missing", ["dependency_missing"], atomic_exit

    if atomic_exit is not None and atomic_exit != 0:
        return "not_confirmed", [f"atomic_exit:{atomic_exit}"], atomic_exit

    if any(re.search(pattern, lower, flags=re.IGNORECASE) for pattern in _EXECUTION_ERROR_PATTERNS):
        return "not_confirmed", ["execution_error_in_output"], atomic_exit

    if process_status == "success":
        return "executed_unverified", [], atomic_exit

    return "error", [f"runner_status:{process_status or 'unknown'}"], atomic_exit


_REMOTE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()

$target = $env:MAGI_TARGET
$user = $env:MAGI_USER
$secret = $env:MAGI_SECRET
$technique = $env:MAGI_TECHNIQUE
$testNumber = [int]$env:MAGI_TEST_NUMBER
$port = [int]$env:MAGI_WINRM_PORT
$useHttps = ($env:MAGI_WINRM_HTTPS -eq '1')

$secure = ConvertTo-SecureString $secret -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $secure)
$session = $null
$trustedChanged = $false
$oldTrusted = $null

try {
    $sessionParams = @{
        ComputerName = $target
        Credential = $cred
        Authentication = 'Negotiate'
        ErrorAction = 'Stop'
        SessionOption = (New-PSSessionOption -OpenTimeout 8000 -OperationTimeout 180000)
    }
    if ($port -gt 0) { $sessionParams['Port'] = $port }
    if ($useHttps) { $sessionParams['UseSSL'] = $true }

    try {
        $session = New-PSSession @sessionParams
    } catch {
        $firstError = $_.Exception.Message
        if (-not $useHttps -and ($firstError -match 'TrustedHosts|WinRM client cannot process|cannot be verified')) {
            try {
                $oldTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
                $items = @()
                if ($oldTrusted) { $items = @($oldTrusted -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                if ($items -notcontains $target -and $items -notcontains '*') {
                    $newTrusted = (@($items + $target) -join ',')
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newTrusted -Force -ErrorAction Stop
                    $trustedChanged = $true
                }
                $session = New-PSSession @sessionParams
            } catch {
                Write-Error ("MAGI_REMOTE_SESSION_ERROR::" + $_.Exception.Message)
                exit 41
            }
        } else {
            Write-Error ("MAGI_REMOTE_SESSION_ERROR::" + $firstError)
            exit 41
        }
    }

    $remoteRoot = 'C:\ProgramData\Magi\AtomicRuntime'
    $remoteModules = Join-Path $remoteRoot 'Modules'
    $remoteModule = Join-Path $remoteModules 'Invoke-AtomicRedTeam'
    $remoteAtomics = Join-Path $remoteRoot 'atomics'
    $remoteTechnique = Join-Path $remoteAtomics $technique

    Invoke-Command -Session $session -ArgumentList $remoteRoot,$remoteModules,$remoteModule,$remoteAtomics,$remoteTechnique -ScriptBlock {
        param($root,$modules,$module,$atomics,$tech)
        New-Item -ItemType Directory -Path $root,$modules,$module,$atomics -Force | Out-Null
        if (Test-Path $tech) { Remove-Item $tech -Recurse -Force -ErrorAction SilentlyContinue }
    } | Out-Null

    $module = Get-Module -ListAvailable Invoke-AtomicRedTeam | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        Write-Error 'MAGI_RUNNER_DEPENDENCY_ERROR::Invoke-AtomicRedTeam module not found on Runner.'
        exit 42
    }
    $moduleBase = $module.ModuleBase
    Copy-Item -Path (Join-Path $moduleBase '*') -Destination $remoteModule -Recurse -Force -ToSession $session

    $candidates = @(
        'C:\AtomicRedTeam\atomics',
        'C:\Program Files\Magi Runner\atomic-red-team\atomics',
        'C:\Program Files\Magi\Runner\atomic-red-team\atomics'
    )
    $localAtomics = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $localAtomics) {
        Write-Error 'MAGI_RUNNER_DEPENDENCY_ERROR::Atomic Red Team atomics folder not found on Runner.'
        exit 43
    }
    $localTechnique = Join-Path $localAtomics $technique
    if (-not (Test-Path $localTechnique)) {
        Write-Error ("MAGI_RUNNER_DEPENDENCY_ERROR::Technique folder not found: " + $localTechnique)
        exit 44
    }
    Copy-Item -Path $localTechnique -Destination $remoteAtomics -Recurse -Force -ToSession $session

    $remoteResult = Invoke-Command -Session $session -ArgumentList $technique,$testNumber,$remoteAtomics,$remoteModule -ScriptBlock {
        param($techniqueId,$number,$atomicsPath,$modulePath)
        $ErrorActionPreference = 'Continue'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
        $OutputEncoding = [System.Text.UTF8Encoding]::new()
        $env:PSModulePath = "$modulePath;$env:PSModulePath"

        $manifest = Join-Path $modulePath 'Invoke-AtomicRedTeam.psd1'
        if (Test-Path $manifest) {
            Import-Module $manifest -Force -ErrorAction Stop
        } else {
            Import-Module Invoke-AtomicRedTeam -Force -ErrorAction Stop
        }

        Write-Output ("MAGI_REMOTE_HOST=" + $env:COMPUTERNAME)
        Write-Output "MAGI_PREREQ_BEGIN"
        try {
            Invoke-AtomicTest $techniqueId -TestNumbers $number -GetPrereqs -PathToAtomicsFolder $atomicsPath 2>&1
        } catch {
            Write-Output ("MAGI_PREREQ_EXCEPTION::" + $_.Exception.Message)
        }
        Write-Output "MAGI_PREREQ_END"

        Write-Output "MAGI_EXECUTE_BEGIN"
        Invoke-AtomicTest $techniqueId -TestNumbers $number -PathToAtomicsFolder $atomicsPath 2>&1
        Write-Output "MAGI_EXECUTE_END"
    }

    $remoteResult | Out-String -Width 4096
    exit 0
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($trustedChanged) {
        try { Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($oldTrusted -as [string]) -Force -ErrorAction SilentlyContinue } catch {}
    }
}
'''


def _run_remote_powershell(target: str, credential: dict[str, Any], technique_id: str, test_number: int, workdir: str, timeout_seconds: int) -> ExecutionResult:
    started = _now()
    port, use_https = _target_port(credential)
    reachable, reach_error = _winrm_reachable(target, port)
    common = {
        "atomic_technique_id": technique_id,
        "atomic_test_number": int(test_number),
        "atomic_action": "execute",
        "execution_scope": "target_remote",
        "requested_target": target,
        "remote_transport": "winrm_https" if use_https else "winrm_http",
        "winrm_port": port,
        "credential_id": credential.get("id"),
        "credential_name": credential.get("name"),
        "attempted_real_test": False,
        "executed_real_test": False,
    }
    if not reachable:
        common.update({
            "confirmation_status": "target_unreachable",
            "outcome_signals": ["winrm_unreachable"],
            "reachability_error": reach_error,
        })
        return _result(
            started=started,
            status="failed",
            exit_code=10,
            stderr=f"TARGET_UNREACHABLE: {target}:{port} sem conectividade WinRM. {reach_error or ''}".strip(),
            metadata=common,
        )

    identity = _identity(credential)
    secret = str(credential.get("secret") or "")
    if not identity or not secret:
        common.update({"confirmation_status": "authentication_failed", "outcome_signals": ["credential_incomplete"]})
        return _result(
            started=started,
            status="failed",
            exit_code=11,
            stderr="AUTHENTICATION_FAILED: credencial Windows/WinRM incompleta.",
            metadata=common,
        )

    env = os.environ.copy()
    env.update({
        "MAGI_TARGET": target,
        "MAGI_USER": identity,
        "MAGI_SECRET": secret,
        "MAGI_TECHNIQUE": technique_id,
        "MAGI_TEST_NUMBER": str(int(test_number)),
        "MAGI_WINRM_PORT": str(port),
        "MAGI_WINRM_HTTPS": "1" if use_https else "0",
    })

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _REMOTE_SCRIPT],
            cwd=workdir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(30, timeout_seconds + 90),
            env=env,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        common.update({
            "confirmation_status": "error",
            "outcome_signals": ["remote_timeout"],
            "attempted_real_test": "MAGI_EXECUTE_BEGIN" in stdout,
            "executed_real_test": False,
        })
        return _result(started=started, status="timeout", exit_code=None, stdout=stdout, stderr=stderr, metadata=common)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined = f"{stdout}\n{stderr}"

    if proc.returncode != 0:
        if proc.returncode == 41 or "MAGI_REMOTE_SESSION_ERROR" in combined:
            low = combined.lower()
            auth = any(s in low for s in ["access is denied", "usuário ou senha", "user name or password", "logon failure", "authentication"])
            confirmation = "authentication_failed" if auth else "remote_transport_error"
            signal = "authentication_failed" if auth else "remote_session_error"
        elif proc.returncode in {42, 43, 44} or "MAGI_RUNNER_DEPENDENCY_ERROR" in combined:
            confirmation = "runner_dependency_error"
            signal = "runner_dependency_error"
        else:
            confirmation = "error"
            signal = f"powershell_exit:{proc.returncode}"
        common.update({
            "confirmation_status": confirmation,
            "outcome_signals": [signal],
            "attempted_real_test": "MAGI_EXECUTE_BEGIN" in combined,
            "executed_real_test": False,
        })
        return _result(started=started, status="failed", exit_code=proc.returncode, stdout=stdout, stderr=stderr, metadata=common)

    confirmation, signals, atomic_exit = _classify_remote_atomic(combined, "success", proc.returncode)
    attempted = "MAGI_EXECUTE_BEGIN" in combined
    remote_host_match = re.search(r"MAGI_REMOTE_HOST=([^\r\n]+)", combined)
    remote_host = remote_host_match.group(1).strip() if remote_host_match else None

    executed = attempted and confirmation not in {"dependency_missing", "error", "runner_dependency_error"}
    final_status = "success"
    if confirmation == "dependency_missing":
        final_status = "failed"
    elif confirmation == "not_confirmed" and atomic_exit not in (None, 0):
        final_status = "failed"

    common.update({
        "confirmation_status": confirmation,
        "outcome_signals": signals,
        "atomic_exit_code": atomic_exit,
        "attempted_real_test": attempted,
        "executed_real_test": executed,
        "execution_host": remote_host or target,
        "remote_host": remote_host,
    })
    effective_exit = atomic_exit if final_status == "failed" and atomic_exit is not None else proc.returncode
    return _result(started=started, status=final_status, exit_code=effective_exit, stdout=stdout, stderr=stderr, metadata=common)


class AtomicExecutor:
    name = "atomic"

    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        payload = job.get("payload") or {}
        technique_id = job.get("technique_id") or payload.get("technique_id")
        test_number = job.get("test_number") or payload.get("test_number") or payload.get("atomic_test_number") or 1
        if not technique_id:
            raise ValueError("Atomic job requires technique_id")

        get_prereqs = bool(payload.get("get_prereqs", False))
        cleanup = bool(payload.get("cleanup", False))
        if get_prereqs or cleanup:
            raise ValueError("Sprint 4.0.5: prereq/cleanup isolados não usam o fluxo de execução Atomic remoto.")

        target = str(job.get("target") or payload.get("target_host") or "").strip()
        credential = payload.get("credential") or {}
        if not target:
            raise ValueError("Atomic remoto requer target.")
        if not credential:
            raise ValueError("Atomic remoto requer credencial transitória.")

        return _run_remote_powershell(
            target=target,
            credential=credential,
            technique_id=str(technique_id),
            test_number=int(test_number),
            workdir=workdir,
            timeout_seconds=timeout_seconds,
        )
