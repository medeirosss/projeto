from __future__ import annotations

from typing import Any

from app.repositories.validation_repository import list_executions, list_tasks, upsert_repository, upsert_task, get_execution
from app.repositories.runner_repository import get_single_online_runner, get_runner_job_result


ATTACK_SIMULATIONS: list[dict[str, Any]] = [
    {
        "task_key": "MAGI-ATK-END-005",
        "name": "SMB Anonymous Session Validation",
        "description": "Valida uma sessão SMB nula/anônima contra IPC$ sem fornecer usuário, senha ou Credential Profile. Não grava arquivos no alvo.",
        "category": "Endpoint", "platform": "Windows", "executor": "attack_simulation", "impact": "safe",
        "detection": {"type": "smb_anonymous_session", "port": 445},
        "remediation": "Desabilite acesso anônimo/null session desnecessário e restrinja SMB às origens autorizadas.",
        "metadata": {"attack_phase":"access_validation","safe_mode":True,"credential_requirement":"NONE","credential_required":False,"provider":"magi_native","changes_target":False,"remote_evidence":"NOT_SUPPORTED"},
    },
    {
        "task_key": "MAGI-ATK-END-001",
        "name": "RDP Protocol Reachability",
        "description": "Simula a primeira etapa de movimento lateral via RDP realizando somente negociação de protocolo, sem autenticação e sem abertura de sessão.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "rdp_negotiation", "port": 3389},
        "remediation": "Restrinja RDP por segmentação, firewall, VPN, NLA e MFA; monitore tentativas provenientes de segmentos não administrativos.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-END-002",
        "name": "WinRM HTTP Protocol Reachability",
        "description": "Simula descoberta de uma superfície de administração WinRM usando WS-Management Identify, sem autenticar ou executar comandos.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "winrm_identify", "port": 5985, "tls": False},
        "remediation": "Restrinja WinRM às origens administrativas necessárias e monitore acessos fora da rede de gestão.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-END-003",
        "name": "WinRM HTTPS Protocol Reachability",
        "description": "Simula descoberta de WinRM HTTPS via WS-Management Identify, sem autenticação e sem execução remota.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "winrm_identify", "port": 5986, "tls": True},
        "remediation": "Restrinja WinRM HTTPS por ACL/firewall e valide certificados e autenticação forte.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-END-004",
        "name": "SMB Protocol Reachability",
        "description": "Simula reconhecimento de uma rota potencial de movimento lateral confirmando somente a superfície TCP/445. Não monta compartilhamentos nem grava arquivos.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "tcp_control_plane", "port": 445},
        "remediation": "Bloqueie SMB entre segmentos que não precisam compartilhar arquivos e limite administração remota a redes autorizadas.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-AD-001",
        "name": "LDAP Protocol Reachability",
        "description": "Simula reconhecimento inicial de serviços de diretório confirmando a disponibilidade do LDAP sem consulta de objetos e sem bind autenticado.",
        "category": "Active Directory",
        "platform": "Domain Controller",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "tcp_control_plane", "port": 389},
        "remediation": "Segmente o acesso aos controladores de domínio e restrinja LDAP a redes e sistemas que realmente necessitam do serviço.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-AD-002",
        "name": "LDAPS Protocol Reachability",
        "description": "Simula reconhecimento do canal LDAPS apenas pela disponibilidade da porta, sem consultas ao diretório.",
        "category": "Active Directory",
        "platform": "Domain Controller",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "tcp_control_plane", "port": 636},
        "remediation": "Mantenha LDAPS restrito aos sistemas autorizados e monitore origens inesperadas acessando controladores de domínio.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-AD-003",
        "name": "Kerberos Protocol Reachability",
        "description": "Simula reconhecimento de infraestrutura Kerberos confirmando a disponibilidade TCP/88 sem solicitar tickets ou testar credenciais.",
        "category": "Active Directory",
        "platform": "Domain Controller",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "tcp_control_plane", "port": 88},
        "remediation": "Restrinja acesso aos controladores de domínio por segmentação e monitore tráfego Kerberos proveniente de redes inesperadas.",
        "metadata": {"attack_phase": "credential_access_path", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-NET-001",
        "name": "SSH Protocol Reachability",
        "description": "Simula reconhecimento de uma rota potencial de movimento lateral lendo somente o banner inicial do SSH, sem autenticação.",
        "category": "Network Node",
        "platform": "Linux/Network",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "protocol_banner", "port": 22},
        "remediation": "Restrinja SSH às redes de administração, utilize autenticação forte e monitore origens não autorizadas.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-NET-002",
        "name": "Telnet Protocol Reachability",
        "description": "Simula reconhecimento de gerenciamento legado lendo somente a resposta inicial do serviço Telnet, quando disponível.",
        "category": "Network Node",
        "platform": "Network",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "protocol_banner", "port": 23},
        "remediation": "Desabilite Telnet e use SSH ou outro canal de administração protegido.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-APP-001",
        "name": "HTTP Telemetry Canary",
        "description": "Envia uma requisição HTTP benigna identificada como MAGI para validar visibilidade de WAF, proxy, aplicação e telemetria de segurança. Não contém exploit.",
        "category": "Application",
        "platform": "Web",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "http_canary", "port": 80, "tls": False, "path": "/magi-attack-simulation"},
        "remediation": "Garanta que WAF/proxy/SIEM registrem a requisição e que a aplicação não exponha rotas desnecessárias.",
        "metadata": {"attack_phase": "initial_access_telemetry", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-APP-002",
        "name": "HTTPS Telemetry Canary",
        "description": "Envia uma requisição HTTPS benigna marcada como MAGI para validar a cadeia de observabilidade sem explorar a aplicação.",
        "category": "Application",
        "platform": "Web",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "http_canary", "port": 443, "tls": True, "path": "/magi-attack-simulation"},
        "remediation": "Valide logging e correlação no WAF/proxy/SIEM para origens e padrões de acesso inesperados.",
        "metadata": {"attack_phase": "initial_access_telemetry", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-APP-003",
        "name": "HTTP Method Discovery",
        "description": "Executa OPTIONS em uma rota canário para simular reconhecimento de métodos HTTP, sem alteração de estado.",
        "category": "Application",
        "platform": "Web",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "http_options", "port": 80, "tls": False, "path": "/"},
        "remediation": "Revise métodos HTTP expostos, desabilite os não utilizados e monitore enumeração de métodos.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": False},
    },
    {
        "task_key": "MAGI-ATK-APP-004",
        "name": "HTTPS Benign POST Telemetry",
        "description": "Envia um POST JSON inofensivo para uma rota canário, permitindo validar observabilidade de tráfego de aplicação sem executar payload malicioso.",
        "category": "Application",
        "platform": "Web",
        "executor": "attack_simulation",
        "impact": "low",
        "detection": {"type": "http_canary_post", "port": 443, "tls": True, "path": "/magi-attack-simulation"},
        "remediation": "Valide logging, WAF e controles de método/rota para requisições inesperadas.",
        "metadata": {"attack_phase": "execution_telemetry", "safe_mode": True, "credential_required": False},
    },
    {"task_key":"MAGI-ATK-END-102","name":"SMB Authenticated Access Validation","description":"Valida autenticação SMB controlada via IPC$ sem payload remoto.","category":"Endpoint","platform":"Windows","executor":"credential_validate","impact":"low","detection":{"type":"smb_auth","port":445},"remediation":"Restrinja SMB e reutilização de credenciais administrativas entre segmentos.","metadata":{"attack_phase":"lateral_access","safe_mode":True,"credential_required":True,"campaign_only":True}},
    {"task_key":"MAGI-ATK-END-103","name":"SSH Authenticated Access Validation","description":"Valida autenticação SSH e executa apenas hostname como prova benigna de acesso.","category":"Endpoint","platform":"Linux/Unix","executor":"credential_validate","impact":"low","detection":{"type":"ssh_auth","port":22},"remediation":"Restrinja SSH, use autenticação forte e contas administrativas separadas.","metadata":{"attack_phase":"lateral_access","safe_mode":True,"credential_required":True,"campaign_only":True}},
    {"task_key":"MAGI-ATK-NET-101","name":"SNMP v2c Discovery Validation","description":"Valida community SNMP v2c e coleta sysName.0; é discovery e não comprometimento.","category":"Network Node","platform":"Network","executor":"credential_validate","impact":"low","detection":{"type":"snmp_v2c","port":161,"transport":"udp"},"remediation":"Restrinja SNMP às redes de gestão; prefira SNMPv3 quando suportado.","metadata":{"attack_phase":"discovery","safe_mode":True,"credential_required":True,"campaign_only":True}},
    {"task_key":"MAGI-ATK-END-104","name":"WinRM Authenticated Access Validation","description":"Valida autenticação WinRM e execução benigna de hostname sem artefato remoto.","category":"Endpoint","platform":"Windows","executor":"credential_validate","impact":"low","detection":{"type":"winrm_auth","port":5985},"remediation":"Restrinja WinRM às redes administrativas e use controles de privilégio.","metadata":{"attack_phase":"lateral_access","safe_mode":True,"credential_required":True,"campaign_only":True}},
    {
        "task_key": "MAGI-ATK-END-101",
        "name": "WinRM Lateral Movement Path Validation",
        "description": "Valida um salto lateral controlado Host A → Host B. O Runner autentica no Host A, cria/verifica/remove um artefato benigno e então o Host A inicia uma nova sessão WinRM para o Host B, repetindo a evidência e o cleanup.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "attack_simulation",
        "impact": "medium",
        "requires_admin": True,
        "detection": {"type": "winrm_lateral_path", "port": 5985, "tls": False},
        "remediation": "Restrinja WinRM e administração remota por segmentação, firewall, JEA/PAM e contas administrativas separadas; impeça reutilização de credenciais administrativas entre endpoints.",
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": True, "secondary_target_required": True, "creates_benign_artifact": True, "automatic_cleanup": True, "scope_engine": "5.2"},
    },

    {
        "task_key": "MAGI-M-ATK-END-001",
        "name": "SMB Version Detection",
        "description": "Executa o scanner SMB Version do Metasploit contra um único alvo e normaliza versão SMB, dialect, signing, criptografia, versão provável do Windows e domínio de autenticação.",
        "category": "Endpoint",
        "platform": "Windows",
        "executor": "metasploit",
        "impact": "safe",
        "detection": {"type": "metasploit_module", "module": "auxiliary/scanner/smb/smb_version", "port": 445},
        "remediation": "Restrinja SMB às redes necessárias, mantenha assinatura SMB conforme política e elimine exposição de TCP/445 entre segmentos sem necessidade.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": False, "provider": "metasploit", "payload": False, "changes_target": False, "cleanup_supported": False, "execution_scope": "target_remote"},
    },
    {
        "task_key": "MAGI-M-ATK-AD-001",
        "name": "Kerberos Authentication Validation",
        "description": "Valida uma única credencial Kerberos informada pelo operador contra o controlador de domínio selecionado. Não executa brute force nem listas de usuários/senhas.",
        "category": "Active Directory",
        "platform": "Domain Controller",
        "executor": "metasploit",
        "impact": "low",
        "detection": {"type": "metasploit_module", "module": "auxiliary/scanner/kerberos/kerberos_login", "port": 88},
        "remediation": "Revise políticas de autenticação, bloqueio de conta e exposição do serviço Kerberos. Use credenciais de laboratório durante validações.",
        "metadata": {"attack_phase": "credential_validation", "safe_mode": True, "credential_required": True, "provider": "metasploit", "single_credential_only": True, "payload": False, "changes_target": False, "cleanup_supported": False, "execution_scope": "target_remote"},
    },
    {
        "task_key": "MAGI-M-ATK-APP-001",
        "name": "HTTP Methods Detection",
        "description": "Executa o módulo HTTP OPTIONS do Metasploit contra uma URL HTTP/HTTPS completa para identificar métodos HTTP anunciados, sem alteração de estado.",
        "category": "Application",
        "platform": "Web",
        "executor": "metasploit",
        "impact": "safe",
        "detection": {"type": "metasploit_module", "module": "auxiliary/scanner/http/options", "port": 80, "path": "/", "ssl": False},
        "remediation": "Desabilite métodos HTTP desnecessários e aplique controles de método/rota no servidor web, proxy ou WAF.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": False, "provider": "metasploit", "target_type": "url", "supported_schemes": ["http", "https"], "payload": False, "changes_target": False, "cleanup_supported": False, "execution_scope": "target_remote"},
    },
    {
        "task_key": "MAGI-M-ATK-NET-001",
        "name": "SNMP Enumeration",
        "description": "Executa enumeração SNMP v2c com uma única community fornecida pelo operador e coleta informações do dispositivo sem executar SNMP SET.",
        "category": "Network Node",
        "platform": "Network",
        "executor": "metasploit",
        "impact": "low",
        "detection": {"type": "metasploit_module", "module": "auxiliary/scanner/snmp/snmp_enum", "port": 161, "transport": "udp"},
        "remediation": "Restrinja SNMP às redes de gestão, utilize communities não padrão e prefira SNMPv3 quando suportado.",
        "metadata": {"attack_phase": "discovery", "safe_mode": True, "credential_required": True, "provider": "metasploit", "credential_type": "snmp", "payload": False, "changes_target": False, "cleanup_supported": False, "execution_scope": "target_remote"},
    },
]


def sync_attack_simulator() -> dict[str, Any]:
    upsert_repository({
        "repository_key": "magi_attack",
        "name": "MAGI Attack Simulator",
        "provider": "magi",
        "description": "Catálogo de Attack/Pentest do MAGI: técnicas nativas e providers externos controlados.",
        "available": True,
        "metadata": {
            "execution": "runner",
            "version": "5.6.4.1",
            "semantics": "attack_simulation",
            "safe_mode": True,
            "destructive": False,
            "credential_execution": True,
        },
    })
    for task in ATTACK_SIMULATIONS:
        meta=dict(task.get('metadata') or {})
        meta['credential_requirement']=str(meta.get('credential_requirement') or ('REQUIRED' if meta.get('credential_required') else 'NONE')).upper()
        meta['credential_required']=(meta['credential_requirement']=='REQUIRED')
        # Remote evidence is opt-in and only allowed for explicitly capable authenticated native transports.
        if 'remote_evidence' not in meta:
            key=str(task.get('task_key') or '')
            meta['remote_evidence']='SUPPORTED' if key in {'MAGI-ATK-END-102','MAGI-ATK-END-104'} else 'NOT_SUPPORTED'
        task={**task,'metadata':meta}
        upsert_task({"repository_key": "magi_attack", **task, "approved": True, "enabled": True, "requires_admin": bool(task.get("requires_admin", False))})
    return {"success": True, "simulations": len(ATTACK_SIMULATIONS)}


def attack_catalog(search: str | None = None, category: str | None = None) -> dict[str, Any]:
    return {"success": True, "simulations": [x for x in list_tasks("magi_attack", search, category) if not (x.get("metadata") or {}).get("campaign_only")]}


def attack_history(limit: int = 100) -> dict[str, Any]:
    rows = [r for r in list_executions(limit=max(limit * 3, 100)) if r.get("repository_key") == "magi_attack"][:limit]
    return {"success": True, "executions": rows}


def provider_status() -> dict[str, Any]:
    runner = get_single_online_runner()
    if not runner:
        return {"success": True, "runner_online": False, "providers": {"magi_native": {"available": False}, "metasploit": {"available": False, "message": "Nenhum Runner online."}}}
    metadata = runner.get("metadata") or {}
    capabilities = metadata.get("capabilities") or {}
    msf = capabilities.get("metasploit") or {}
    return {
        "success": True,
        "runner_online": True,
        "runner_id": runner.get("runner_id"),
        "providers": {
            "magi_native": {"available": True},
            "metasploit": {
                "available": bool(msf.get("available")),
                "version": msf.get("version"),
                "path": msf.get("path"),
                "message": msf.get("message"),
            },
        },
    }


def _sanitize_log_text(text: str | None, secrets: list[str] | None = None) -> str:
    import re
    safe = str(text or "")
    for secret in sorted(set(secrets or []), key=len, reverse=True):
        if secret:
            safe = safe.replace(secret, "********")
    safe = re.sub(r"(?im)^(\s*(?:PASSWORD|PASS|COMMUNITY|TOKEN|SECRET)\s*=>\s*).+$", r"\1********", safe)
    safe = re.sub(r"(?i)(with password\s+)(\S+)", r"\1********", safe)
    safe = re.sub(r"(?i)(Hash:\s*)\$krb5[^\r\n]+", r"\1[REDACTED_KERBEROS_MATERIAL]", safe)
    return safe


def attack_execution_log(execution_id: int) -> dict[str, Any]:
    execution = get_execution(int(execution_id))
    if not execution or execution.get("repository_key") != "magi_attack":
        raise ValueError("Execução do Attack Simulator não encontrada.")

    evidence = execution.get("evidence") or {}
    logs = evidence.get("logs") or {}
    stdout = logs.get("stdout") or ""
    stderr = logs.get("stderr") or ""
    job = None

    # Compatibility fallback for executions created in 5.5.0. New executions
    # read the durable sanitized copy from validation_task_executions.evidence.
    if (not stdout and not stderr) and execution.get("runner_job_id"):
        job = get_runner_job_result(int(execution["runner_job_id"]))
        result = (job or {}).get("result") or {}
        stdout = result.get("stdout") or ""
        stderr = result.get("stderr") or ""

    secrets: list[str] = []
    payload = (job or {}).get("payload") or {}
    credential_id = payload.get("credential_id")
    if credential_id:
        try:
            from app.services.credentials_service import get_credential_by_id
            credential = get_credential_by_id(credential_id, include_secret=True) or {}
            if credential.get("password"):
                secrets.append(str(credential.get("password")))
        except Exception:
            pass

    stdout = _sanitize_log_text(stdout, secrets)
    stderr = _sanitize_log_text(stderr, secrets)
    meta = dict(evidence)
    meta.pop("logs", None)

    return {
        "success": True,
        "execution": {
            "id": execution.get("id"),
            "execution_uuid": execution.get("execution_uuid"),
            "task_key": execution.get("task_key"),
            "task_name": execution.get("task_name"),
            "provider": (meta.get("provider") or ("metasploit" if str(execution.get("task_key") or "").startswith("MAGI-M-ATK-") else "magi_native")),
            "target": execution.get("target"),
            "runner_id": execution.get("runner_id"),
            "runner_job_id": execution.get("runner_job_id"),
            "status": execution.get("status"),
            "finding_status": execution.get("finding_status"),
            "finding_message": execution.get("finding_message"),
            "created_at": execution.get("created_at"),
            "started_at": execution.get("started_at"),
            "finished_at": execution.get("finished_at"),
        },
        "stdout": stdout,
        "stderr": stderr,
        "evidence": meta,
    }
