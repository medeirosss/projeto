## 2.11.2 / Sprint 2.1.1
- DNS enrichment opcional via Runner.
- Consulta PTR em DNS primário/secundário configuráveis.
- Fallback para DNS do sistema.
- Persistência de dns_name e hostname_source.

# Changelog

## 0.8.0-validation-history

### Added
- Histórico de validações Atomic com filtros por texto livre, técnica, runner, status, solicitante e período.
- Contagem total de registros no endpoint `/api/validations/atomic/executions`.
- Campo `duration_seconds` no retorno de histórico e detalhe de execução.
- Botão de detalhes por execução no frontend, exibindo payload, evidência, stdout, stderr, exit code, runner e UUID.
- Documento `ROADMAP.md` como escopo oficial até a Golden Image 1.0.
- Documento `TEST_PLAN.md` com critérios de validação da sprint.
- Documento `UPGRADE.md` com instruções de atualização.
- Arquivo `VERSION` para controle de release.

### Changed
- A área de execuções da tela de validações foi reposicionada como histórico operacional, não apenas lista de previews.
- O endpoint de execuções continua retrocompatível, mas agora aceita filtros opcionais.

### Notas
- Não há migration obrigatória nesta sprint.
- A regra de produto permanece: o Magi não bloqueia por risco, reboot, dependência ou plataforma; o bloqueio real é aprovação/admin ou teste desabilitado.

## UI Tasks / History patch (2026-07-24)
- Renamed main navigation "Validações" to "Tarefas".
- Renamed home navigation item "Centric" to "MAGI".
- Split task catalog and job history into separate sidebar views.
- Removed Runner selection from task execution.
- Backend automatically selects the most recently active online Runner (2-minute heartbeat window).
- Added mandatory dynamic target (IP or hostname) to execution jobs.
- Replaced Approve/Prepare/Execute LAB controls with a single Execute action.
- Kept Runner status/listing under Settings unchanged.

## Sprint 1 — Alvos e descoberta Nmap (2026-07-24)

- Adicionada a aba **Alvos** com nome, IP, MAC e última detecção.
- Adicionada descoberta local por IPv4 ou CIDR usando Nmap no backend.
- Adicionadas correlação por MAC, hostname e IP e preservação do histórico de endereços.
- Adicionadas as tabelas `targets`, `target_addresses` e `discovery_runs`.
- Adicionados endpoints `/api/targets`, `/api/targets/discover` e `/api/targets/discovery-runs`.
- Nmap incorporado ao Dockerfile e capability `NET_RAW` adicionada ao Compose.

## Sprint 1 v2 — Discovery Engine gerenciado (2026-07-26)

- Separada a área **Alvos** em **Máquinas descobertas** e **Scan**.
- Removido o cadastro direto a partir do IP digitado; somente respostas diretas aceitas pelo parser são persistidas.
- Nmap ajustado para descoberta rápida com `-sn`, `-T4`, `--max-retries 1`, `--reason` e sondagens ICMP/TCP.
- Adicionadas configurações persistentes de scan para host individual ou CIDR.
- Adicionados scans manuais e agendados, com intervalo mínimo de 15 minutos.
- Adicionadas ações de executar agora, ativar, pausar e excluir scan.
- Adicionada exclusão lógica de host; um host reaparece caso seja descoberto novamente.
- Adicionada opção de remover alvos exclusivos ao excluir um scan.
- Adicionado histórico com duração, origem manual/agendada, endereços verificados e hosts confirmados.
- Adicionado scheduler interno com limite de duas execuções concorrentes por ciclo.
- Nova migration Alembic: `20260726_0014`.
