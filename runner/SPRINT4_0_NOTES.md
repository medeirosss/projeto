# MAGI Sprint 4.0 — Repository, Planner, Evidence & Remediation

## Objetivo
A Sprint 4.0 cria a camada de orquestração de validações do MAGI. O produto deixa de depender de um único catálogo e passa a tratar checks como tarefas provenientes de providers.

## Providers
- **MAGI Security Checks**: provider nativo e executável nesta build.
- **Atomic Red Team**: integração existente preservada; aparece como provider do ecossistema sem substituir o fluxo Atomic já homologado.
- **Nuclei Templates**: provider registrado como `prepared`; a sincronização/binário Nuclei não é ativada nesta build para não introduzir uma dependência não homologada.

## Checks nativos iniciais
Os checks da 4.0 são não destrutivos e observam exposição TCP a partir do Runner: RDP 3389, SMB 445, WinRM 5985/5986, SSH 22 e Telnet 23.

Uma porta aberta significa **exposição observável a partir da posição de rede do Runner**, não prova por si só vulnerabilidade explorável. A evidência registra essa distinção.

## Fluxo
1. UI solicita `plan`.
2. Planner valida target, tarefa, aprovação e Runner online.
3. Backend cria `runner_job` do tipo `security_check`.
4. Runner executa o check e devolve evidência estruturada.
5. Backend persiste resultado em `validation_task_executions`.
6. Resultado mantém remediation junto da execução.

## Banco
Migration: `20260810_0025_sprint4_repository_planner.py`.

Novas tabelas:
- `validation_repositories`
- `validation_tasks`
- `validation_task_executions`

## Runner
Novo executor: `security_check`.

Configurações antigas são migradas em memória: quando `deep_inventory` já estiver permitido, `security_check` é adicionado automaticamente ao carregar `settings.json`.

## Critério de segurança do produto
`impact` é classificação informativa. O Planner não bloqueia uma tarefa por impacto. O bloqueio administrativo continua baseado em `enabled` e `approved`.
