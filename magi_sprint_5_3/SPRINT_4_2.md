# MAGI Sprint 4.2 — Vulnerability Validation Expansion & Hardening

## Runtime Nuclei
- `nuclei.exe` e templates homologados são distribuídos dentro do Runner.
- Atualização automática desabilitada.
- `runtime-manifest.json` registra SHA-256 do engine e marcador de integridade dos templates.
- Doctor valida Engine, Templates e Runtime Integrity.

## MAGI Native Checks
Catálogo Network ampliado para 10 checks:
RDP, SMB, WinRM HTTP/HTTPS, SSH, Telnet, FTP, MSSQL, MySQL e PostgreSQL.
Esses checks representam superfície/exposição, não vulnerabilidade automática.

## Perfis Nuclei
- CVE HTTP/HTTPS
- CVE Network
- Painéis HTTP expostos
- Misconfiguration HTTP
- Technology Detection

## Smart Preflight
O Runner verifica reachability e portas compatíveis antes do Nuclei:
- host inacessível -> TARGET_UNREACHABLE / NOT_EVALUATED
- host acessível sem serviço compatível -> SUCCESS / NOT_APPLICABLE
- serviço compatível -> Nuclei é executado

## Evidence Normalization
Resultados Nuclei normalizam:
- template/name
- severity
- matched_at
- matcher
- CVEs confirmadas
- contagem por severidade
- quantidade de templates selecionados
- targets efetivamente testados

Atomic Red Team permanece congelado para pós-ataque.
