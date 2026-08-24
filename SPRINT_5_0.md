# MAGI Build 5.0 — Attack Simulator Foundation

## Objetivo
A Build 5.0 inaugura o **MAGI Attack Simulator** como módulo separado do Vulnerability Validation. O foco é reproduzir **comportamentos iniciais de ataque de forma remota, controlada e não destrutiva**, produzindo evidências que permitam avaliar exposição e observabilidade do ambiente.

## Decisão arquitetural
- O Runner executa as simulações autonomamente.
- Nenhum repositório externo é necessário em runtime.
- O executor `attack_simulation` usa apenas biblioteca padrão do Python.
- A Build 5.0 não explora CVEs, não faz brute force, não executa comandos remotos e não altera o alvo.
- Atomic Red Team continua congelado e reservado para pós-comprometimento.
- Nuclei continua pertencendo à trilha de Vulnerability Validation, não ao Attack Simulator.

## Catálogo inicial — 13 simulações
### Endpoint
- MAGI-ATK-END-001 — RDP Lateral Movement Surface
- MAGI-ATK-END-002 — WinRM HTTP Lateral Movement Surface
- MAGI-ATK-END-003 — WinRM HTTPS Lateral Movement Surface
- MAGI-ATK-END-004 — SMB Lateral Movement Surface

### Active Directory
- MAGI-ATK-AD-001 — LDAP Domain Services Surface
- MAGI-ATK-AD-002 — LDAPS Domain Services Surface
- MAGI-ATK-AD-003 — Kerberos Authentication Surface

### Network Node
- MAGI-ATK-NET-001 — SSH Lateral Movement Surface
- MAGI-ATK-NET-002 — Telnet Legacy Management Surface

### Application
- MAGI-ATK-APP-001 — HTTP Attack Telemetry Canary
- MAGI-ATK-APP-002 — HTTPS Attack Telemetry Canary
- MAGI-ATK-APP-003 — HTTP Method Discovery Simulation
- MAGI-ATK-APP-004 — HTTPS Benign POST Simulation

## Evidência normalizada
Cada execução registra:
- engine e versão;
- cenário e categoria;
- target solicitado;
- tipo de simulação;
- `safe_mode=true` e `destructive=false`;
- resultado da negociação/probe;
- latência e resposta de protocolo quando aplicável;
- `finding.detected`;
- `confirmation_status`;
- artefato ZIP padrão do Runner.

## UI
Nova página `/attack-simulator` com:
- resumo da Build 5.0;
- filtros por categoria e busca;
- target obrigatório;
- Planejar / Executar;
- histórico dedicado.

## Escopo de segurança da 5.0
A 5.0 **não considera uma porta aberta como comprometimento**. O finding significa que a etapa simulada conseguiu alcançar/negociar com o controle correspondente. A comprovação de movimento lateral autenticado será tratada em uma sprint posterior com canário benigno e cleanup controlado.
