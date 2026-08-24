from __future__ import annotations

from typing import Any

from app.repositories.validation_repository import list_executions, list_tasks, upsert_repository, upsert_task


ATTACK_SIMULATIONS: list[dict[str, Any]] = [
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
        "metadata": {"attack_phase": "lateral_movement", "safe_mode": True, "credential_required": True, "secondary_target_required": True, "creates_benign_artifact": True, "automatic_cleanup": True, "scope_engine": "5.1"},
    },
]


def sync_attack_simulator() -> dict[str, Any]:
    upsert_repository({
        "repository_key": "magi_attack",
        "name": "MAGI Attack Simulator",
        "provider": "magi",
        "description": "Catálogo nativo de simulações remotas, controladas e não destrutivas do MAGI 5.1.",
        "available": True,
        "metadata": {
            "execution": "runner",
            "version": "5.1",
            "semantics": "attack_simulation",
            "safe_mode": True,
            "destructive": False,
            "credential_execution": True,
        },
    })
    for task in ATTACK_SIMULATIONS:
        upsert_task({"repository_key": "magi_attack", **task, "approved": True, "enabled": True, "requires_admin": bool(task.get("requires_admin", False))})
    return {"success": True, "simulations": len(ATTACK_SIMULATIONS)}


def attack_catalog(search: str | None = None, category: str | None = None) -> dict[str, Any]:
    return {"success": True, "simulations": list_tasks("magi_attack", search, category)}


def attack_history(limit: int = 100) -> dict[str, Any]:
    rows = [r for r in list_executions(limit=max(limit * 3, 100)) if r.get("repository_key") == "magi_attack"][:limit]
    return {"success": True, "executions": rows}
