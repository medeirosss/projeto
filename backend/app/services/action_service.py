from __future__ import annotations

import ipaddress
import json
import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
try:
    import winrm
except Exception:  # pywinrm is optional until remote_winrm is used
    winrm = None

from app.config import SCRIPTS_DIR, SECURITY_BACKEND_URL
from app.services.common import write_text_log
from app.services.credentials_service import get_credential_by_name
from app.services.data_service import get_ad_records, get_ec_records
from app.services.alert_service import list_open_alerts, alert_summary, mark_alert_execution_started, register_execution_result, ensure_alert_id, get_alert_by_id
from app.repositories.alerts_repository import get_latest_alert
from app.services.scripts_service import ALLOWED_EXTENSIONS, list_scripts, materialize_script
from app.repositories.executions_repository import create_playbook_execution, update_playbook_execution_result

EXECUTION_TIMEOUT_SECONDS = 120


def get_listener_info() -> Dict[str, Any]:
    path = '/api/actions/inbound-alert'
    return {'path': path}


def get_alert_history() -> List[Dict[str, Any]]:
    # Alert history now comes from PostgreSQL. Keep this function for compatibility with older UI code.
    return list_open_alerts()[:50]


def _append_alert_history(alert_payload: Dict[str, Any]) -> None:
    # No-op: inbound alerts are persisted in PostgreSQL by create_alert_from_inbound().
    return None


def normalize_inbound_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    technique = str(payload.get('technique') or payload.get('mitre_technique') or payload.get('mitre_id') or '').strip()
    tactic = str(payload.get('tactic') or payload.get('mitre_tactic') or '').strip()
    nist = str(payload.get('nist') or payload.get('nist_control') or '').strip()
    severity = str(payload.get('severity') or payload.get('severity_text') or '').strip()
    username = str(
        payload.get('username')
        or payload.get('target_user')
        or payload.get('caller_user_sid')
        or payload.get('user')
        or payload.get('caller_user_name')
        or payload.get('user_display_name')
        or ''
    ).strip()
    event_number = str(payload.get('event_number') or payload.get('event_id') or '').strip()
    display_name = str(payload.get('display_name') or payload.get('event_name') or '').strip()
    event = str(payload.get('event') or event_number or display_name or payload.get('event_type') or '').strip()
    timestamp = str(payload.get('timestamp') or payload.get('date') or payload.get('time') or payload.get('event_time') or datetime.now().isoformat()).strip()
    source_ip = str(
        payload.get('source_ip')
        or payload.get('target_ip')
        or payload.get('IP')
        or payload.get('ip')
        or payload.get('host_ip')
        or ''
    ).strip()
    hostname = str(payload.get('hostname') or payload.get('host_name') or payload.get('machine') or payload.get('host') or '').strip()
    alert_id = ensure_alert_id(payload.get('alert_id'))
    return {
        'alert_id': alert_id,
        'date': timestamp,
        'event': event or 'Inbound Alert',
        'event_number': event_number,
        'display_name': display_name,
        'username': username,
        'target_user': username,
        'technique': technique,
        'tactic': tactic,
        'nist': nist,
        'severity': severity,
        'source_ip': source_ip,
        'target_ip': source_ip,
        'hostname': hostname,
        'raw_payload': payload,
    }

def fetch_security_alerts() -> List[Dict[str, Any]]:
    return list_open_alerts()


def get_alert_summary() -> Dict[str, Any]:
    data = alert_summary()
    alerts = fetch_security_alerts()
    critical = sum(1 for item in alerts if 'alta' in str(item.get('severity') or '').lower() or 'critical' in str(item.get('severity') or '').lower())
    mitre = sum(1 for item in alerts if item.get('technique'))
    return {'total_events': data.get('total', 0), 'mitre_events': mitre, 'critical_events': critical, 'new': data.get('new', 0), 'known': data.get('known', 0), 'resolved': data.get('resolved', 0)}


def get_known_targets() -> Dict[str, List[Dict[str, Any]]]:
    machines: List[Dict[str, Any]] = []
    seen = set()
    for item in get_ec_records():
        hostname = str(item.get('full_name') or '').strip()
        if not hostname or hostname.lower() in seen:
            continue
        seen.add(hostname.lower())
        users = item.get('agent_logged_on_users') or ''
        if isinstance(users, list):
            users_text = ', '.join([str(x) for x in users if x])
        else:
            users_text = str(users)
        machines.append({'hostname': hostname,'ip': str(item.get('IP') or ''),'user': users_text,'resource_id': str(item.get('resource_id') or ''),'source': 'UEM'})
    users: List[Dict[str, Any]] = []
    user_seen = set()
    for machine in machines:
        for raw_user in [u.strip() for u in str(machine.get('user') or '').split(',') if u.strip()]:
            key = raw_user.lower()
            if key in user_seen:
                continue
            user_seen.add(key)
            users.append({'username': raw_user, 'source': 'UEM'})
    for item in get_ad_records():
        hostname = str(item.get('hostname') or item.get('name') or item.get('cn') or '').strip()
        if hostname and hostname.lower() not in seen:
            seen.add(hostname.lower())
            machines.append({'hostname': hostname,'ip': str(item.get('ip') or ''),'user': '','resource_id': '','source': 'AD'})
    return {'machines': machines, 'users': users}


def _safe_script_path(script_name: str) -> Path:
    path = materialize_script(script_name)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError('Script não encontrado.')
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError('Tipo de script não suportado.')
    return path


def _ip_matches_scope(ip_value: str, cidrs: List[str]) -> Optional[bool]:
    ip_text = (ip_value or '').strip()
    if not ip_text:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return None
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def decide_execution_mode(ip_value: str, cidrs: List[str]) -> Dict[str, Any]:
    decision = _ip_matches_scope(ip_value, cidrs)
    if decision is True:
        return {'mode': 'local', 'reason': 'IP dentro do IP Scope configurado.'}
    if decision is False:
        return {'mode': 'external', 'reason': 'IP fora do IP Scope configurado.'}
    return {'mode': 'unknown', 'reason': 'IP ausente ou inválido.'}


def _build_env_payload(context: Dict[str, Any], credential_name: str = '') -> Dict[str, str]:
    env = os.environ.copy()
    for key, value in context.items():
        env_key = ''.join(ch if ch.isalnum() else '_' for ch in str(key).upper())
        env[f'CENTRIC_{env_key}'] = '' if value is None else str(value)
    if credential_name:
        cred = get_credential_by_name(credential_name, include_secret=True)
        if cred:
            env['CENTRIC_EXEC_CREDENTIAL_NAME'] = str(cred.get('name') or '')
            env['CENTRIC_EXEC_USERNAME'] = str(cred.get('username') or '')
            env['CENTRIC_EXEC_PASSWORD'] = str(cred.get('password') or '')
    return env


def _run_script_local(script_path: Path, context: Dict[str, Any], credential_name: str = '') -> Dict[str, Any]:
    ext = script_path.suffix.lower()
    if ext == '.ps1':
        command = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(script_path)]
    elif ext == '.sh':
        command = ['bash', str(script_path)]
    else:
        raise ValueError('Tipo de script não suportado.')
    completed = subprocess.run(command,capture_output=True,text=True,timeout=EXECUTION_TIMEOUT_SECONDS,env=_build_env_payload(context, credential_name),cwd=str(SCRIPTS_DIR))
    return {'command': ' '.join(shlex.quote(part) for part in command),'returncode': completed.returncode,'stdout': completed.stdout[-4000:],'stderr': completed.stderr[-4000:],'success': completed.returncode == 0}




def _credential_requests_winrm(credential_name: str) -> bool:
    if not credential_name:
        return False
    cred = get_credential_by_name(credential_name, include_secret=False)
    return bool(cred and str(cred.get('type') or '').lower() == 'winrm')


def _run_script_winrm(script_path: Path, context: Dict[str, Any], credential_name: str, target: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a PowerShell script on a remote Windows host through WinRM.

    The container stays Linux. Windows-only modules such as ActiveDirectory/RSAT
    run on the remote Windows executor where the script is actually executed.
    """
    if winrm is None:
        raise RuntimeError('pywinrm não está instalado no container. Verifique backend/requirements.txt e refaça o build.')
    if script_path.suffix.lower() != '.ps1':
        raise ValueError('Execução remote_winrm suporta apenas scripts .ps1.')
    cred = get_credential_by_name(credential_name, include_secret=True)
    if not cred:
        raise ValueError('Credencial WinRM não encontrada.')
    if str(cred.get('type') or '').lower() != 'winrm':
        raise ValueError('A credencial selecionada não é do tipo winrm.')

    metadata = cred.get('metadata') if isinstance(cred.get('metadata'), dict) else {}
    host = str(
        target.get('winrm_host')
        or metadata.get('host')
        or target.get('hostname')
        or target.get('ip')
        or context.get('hostname')
        or context.get('ip')
        or ''
    ).strip()
    if not host:
        raise ValueError('Informe o host/IP WinRM na credencial ou no alvo da execução.')
    port = int(metadata.get('port') or target.get('winrm_port') or 5985)
    use_https = bool(metadata.get('use_https', False))
    transport = str(metadata.get('transport') or 'ntlm').strip().lower()
    scheme = 'https' if use_https else 'http'
    endpoint = f'{scheme}://{host}:{port}/wsman'
    username = str(cred.get('username') or '').strip()
    password = str(cred.get('password') or '').strip()
    if not username or not password:
        raise ValueError('Credencial WinRM sem usuário ou senha.')

    script_text = script_path.read_text(encoding='utf-8', errors='ignore')
    env_lines = []
    for key, value in context.items():
        env_key = ''.join(ch if ch.isalnum() else '_' for ch in str(key).upper())
        safe_value = str('' if value is None else value).replace("'", "''")
        env_lines.append(f"$env:CENTRIC_{env_key} = '{safe_value}'")
    wrapped_script = '\n'.join(env_lines) + '\n' + script_text

    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport,
        server_cert_validation='ignore' if use_https else 'validate',
    )
    response = session.run_ps(wrapped_script)
    stdout = (response.std_out or b'').decode('utf-8', errors='replace')
    stderr = (response.std_err or b'').decode('utf-8', errors='replace')
    return {
        'command': f'winrm:{endpoint} powershell -File {script_path.name}',
        'returncode': int(response.status_code),
        'stdout': stdout[-4000:],
        'stderr': stderr[-4000:],
        'success': int(response.status_code) == 0,
        'execution_mode': 'remote_winrm',
        'winrm_endpoint': endpoint,
        'winrm_transport': transport,
    }


def _parse_script_confirmation(result: Dict[str, Any]) -> Dict[str, Any]:
    stdout_text = str(result.get('stdout') or '').strip()
    if not stdout_text:
        return {'confirmed': False, 'success': False, 'message': ''}
    for candidate in [line.strip() for line in stdout_text.splitlines()[::-1] if line.strip()]:
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict) and 'success' in parsed:
            return {'confirmed': True, 'success': bool(parsed.get('success')), 'message': str(parsed.get('message') or '')}
    return {'confirmed': False, 'success': False, 'message': ''}


def _write_execution_log(kind: str, payload: Dict[str, Any], result: Dict[str, Any]) -> str:
    lines = [f'=== {kind.upper()} EXECUTION ===',f'Timestamp: {datetime.now().isoformat()}',f'Mode: {result.get("execution_mode")}',f'Reason: {result.get("decision_reason")}',f'Script: {payload.get("script_name")}',f'Credential: {payload.get("credential_name") or "-"}',f'Target: {payload.get("target", {}).get("hostname") or payload.get("target", {}).get("username") or payload.get("alert", {}).get("hostname") or "-"}',f'IP: {payload.get("target", {}).get("ip") or payload.get("target_ip") or payload.get("alert", {}).get("target_ip") or payload.get("alert", {}).get("source_ip") or "-"}']
    if result.get('command'):
        lines.append(f'Command: {result.get("command")}')
    if result.get('stdout'):
        lines.extend(['--- STDOUT ---', result['stdout']])
    if result.get('stderr'):
        lines.extend(['--- STDERR ---', result['stderr']])
    log = write_text_log('ACTION', '\n'.join(lines))
    return log.name


def execute_manual_action(payload: Dict[str, Any], cidrs: List[str], executed_by: str = 'system') -> Dict[str, Any]:
    script_name = str(payload.get('script_name') or '').strip()
    credential_name = str(payload.get('credential_name') or '').strip()
    target = payload.get('target') or {}
    if not script_name:
        raise ValueError('Selecione um script.')
    script_path = _safe_script_path(script_name)
    variables = payload.get('variables') or {}
    context = {'action_type': 'manual','hostname': target.get('hostname', ''),'ip': target.get('ip', ''),'username': target.get('username', target.get('user', '')),'resource_id': target.get('resource_id', ''),'source': target.get('source', '')}
    context.update({k: v for k, v in variables.items() if v not in (None, '')})
    requested_winrm = _credential_requests_winrm(credential_name) or str(payload.get('execution_type') or '').lower() == 'remote_winrm'
    decision = {'mode': 'remote_winrm', 'reason': 'Credencial/tipo de execução WinRM selecionado.'} if requested_winrm else decide_execution_mode(str(target.get('ip', '')), cidrs)
    result: Dict[str, Any] = {'execution_mode': decision['mode'],'decision_reason': decision['reason'],'script_name': script_name,'target': target,'credential_name': credential_name,'success': False}
    execution_record = create_playbook_execution({
        'script_name': script_name,
        'credential_name': credential_name,
        'target': target.get('hostname') or target.get('username') or target.get('user') or target.get('ip') or '',
        'variables': {**context, 'execution_mode': decision['mode'], 'decision_reason': decision['reason']},
        'status': 'running' if decision['mode'] in {'local', 'remote_winrm'} else 'pending_external',
        'executed_by': executed_by,
    })
    result['execution_id'] = execution_record.get('id')
    if decision['mode'] == 'remote_winrm':
        result.update(_run_script_winrm(script_path, context, credential_name, target))
    elif decision['mode'] == 'local':
        result.update(_run_script_local(script_path, context, credential_name))
    else:
        result.update({'success': True,'pending_external': decision['mode'] != 'local','stdout': '','stderr': '','message': 'Execução encaminhada para fluxo externo (Endpoint Central / n8n).' if decision['mode'] == 'external' else 'Execução pendente. IP inválido ou ausente.'})
    result['log_file'] = _write_execution_log('manual', payload, result)
    result['execution'] = update_playbook_execution_result(result['execution_id'], result)
    return result


def save_last_alert(alert_payload: Dict[str, Any]) -> None:
    # No file persistence in v2. The alert is persisted by the inbound-alert router.
    return None


def get_last_alert() -> Dict[str, Any]:
    return get_latest_alert()


def execute_alert_action(payload: Dict[str, Any], cidrs: List[str], executed_by: str = 'system') -> Dict[str, Any]:
    script_name = str(payload.get('script_name') or '').strip()
    credential_name = str(payload.get('credential_name') or '').strip()
    alert = dict(payload.get('alert') or {})
    raw_payload = alert.get('raw_payload') or {}
    target = dict(payload.get('target') or {})

    target_ip = str(
        target.get('ip')
        or payload.get('target_ip')
        or payload.get('ip')
        or alert.get('target_ip')
        or alert.get('source_ip')
        or raw_payload.get('target_ip')
        or raw_payload.get('IP')
        or raw_payload.get('ip')
        or raw_payload.get('host_ip')
        or ''
    ).strip()
    target_user = str(
        target.get('username')
        or target.get('user')
        or payload.get('target_user')
        or alert.get('target_user')
        or alert.get('username')
        or raw_payload.get('target_user')
        or raw_payload.get('caller_user_sid')
        or raw_payload.get('username')
        or ''
    ).strip()
    target_hostname = str(target.get('hostname') or alert.get('hostname') or raw_payload.get('hostname') or '').strip()
    target_resource_id = str(target.get('resource_id') or '').strip()
    target_source = str(target.get('source') or '').strip()

    alert['alert_id'] = ensure_alert_id(alert.get('alert_id'))
    alert['target_ip'] = target_ip
    alert['source_ip'] = target_ip or str(alert.get('source_ip') or '')
    alert['target_user'] = target_user
    alert['username'] = target_user or str(alert.get('username') or '')
    alert['hostname'] = target_hostname or str(alert.get('hostname') or '')

    if not script_name:
        raise ValueError('Selecione um script.')
    script_path = _safe_script_path(script_name)
    save_last_alert(alert)

    context = {
        'action_type': 'alert',
        'alert_id': alert.get('alert_id', ''),
        'alert_type': alert.get('alert_type', ''),
        'event_type': alert.get('event_type', alert.get('event', '')),
        'event_number': alert.get('event_number', alert.get('event', '')),
        'source_ip': alert.get('source_ip', ''),
        'target_ip': target_ip,
        'ip': target_ip,
        'hostname': alert.get('hostname', ''),
        'username': alert.get('username', ''),
        'target_user': target_user,
        'target': target_user or target_hostname or target_ip,
        'resource_id': target_resource_id,
        'source': target_source,
        'timestamp': alert.get('timestamp', alert.get('date', '')),
        'technique': alert.get('technique', ''),
        'tactic': alert.get('tactic', ''),
        'nist': alert.get('nist', ''),
        'severity': alert.get('severity', ''),
        'raw_alert': json.dumps(alert, ensure_ascii=False),
    }
    variables = payload.get('variables') or {}
    context.update({k: v for k, v in variables.items() if v not in (None, '')})

    requested_winrm = _credential_requests_winrm(credential_name) or str(payload.get('execution_type') or '').lower() == 'remote_winrm'
    decision = {'mode': 'remote_winrm', 'reason': 'Credencial/tipo de execução WinRM selecionado.'} if requested_winrm else decide_execution_mode(target_ip, cidrs)
    mark_alert_execution_started(str(alert.get('alert_id') or ''), script_name, credential_name, decision['mode'], decision['reason'])
    result: Dict[str, Any] = {
        'execution_mode': decision['mode'],
        'decision_reason': decision['reason'],
        'script_name': script_name,
        'credential_name': credential_name,
        'alert': alert,
        'target': target,
        'target_ip': target_ip,
        'target_user': target_user,
        'success': False,
    }
    persisted_alert = get_alert_by_id(str(alert.get('alert_id') or '')) or {}
    execution_record = create_playbook_execution({
        'alert_id': persisted_alert.get('db_id') or persisted_alert.get('id'),
        'script_name': script_name,
        'credential_name': credential_name,
        'target': target_user or target_hostname or target_ip,
        'variables': {**context, 'execution_mode': decision['mode'], 'decision_reason': decision['reason']},
        'status': 'running' if decision['mode'] in {'local', 'remote_winrm'} else 'pending_external',
        'executed_by': executed_by,
    })
    result['execution_id'] = execution_record.get('id')
    if decision['mode'] == 'remote_winrm':
        result.update(_run_script_winrm(script_path, context, credential_name, target))
        confirmation = _parse_script_confirmation(result)
        if confirmation['confirmed']:
            register_execution_result(str(alert.get('alert_id') or ''), confirmation['success'], confirmation['message'], 'playbook')
            result['script_confirmation'] = confirmation
        else:
            result['script_confirmation'] = {'confirmed': False, 'message': 'Script executado via WinRM sem retorno JSON de confirmação.'}
    elif decision['mode'] == 'local':
        result.update(_run_script_local(script_path, context, credential_name))
        confirmation = _parse_script_confirmation(result)
        if confirmation['confirmed']:
            register_execution_result(str(alert.get('alert_id') or ''), confirmation['success'], confirmation['message'], 'playbook')
            result['script_confirmation'] = confirmation
        else:
            result['script_confirmation'] = {'confirmed': False, 'message': 'Script executado sem retorno JSON de confirmação.'}
    else:
        result.update({'success': True,'pending_external': decision['mode'] != 'local','stdout':'','stderr':'','message':'Alerta encaminhado para fluxo externo (Endpoint Central / n8n).' if decision['mode'] == 'external' else 'Alerta sem IP válido para decisão automática.'})
    result['log_file'] = _write_execution_log('alert', payload, result)
    result['execution'] = update_playbook_execution_result(result['execution_id'], result)
    return result
