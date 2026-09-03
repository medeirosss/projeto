## 5.4.0
- Attack Path & Evidence por Campaign, resumo, barriers e rastreabilidade por execução/cycle/job.

## 5.3.12
- Campaign stateful, cycles event-driven (máx. 15 min), branch 10/5/3/0 e controles Ajustar/Próximo ciclo/Excluir.

## 5.3.11
- Corrige Campaign que encerrava após o primeiro ciclo quando não havia `access_confirmed`.
- Seeds iniciais permanecem elegíveis entre ciclos enquanto houver candidatos não testados.
- `scope_exhausted` agora representa esgotamento real dos caminhos disponíveis.

# 5.3.10 - Campaign ICMP Admission Gate

- ICMP Echo Reply passa a ser requisito obrigatório para um IP entrar na Campaign.
- `campaign_probe` executa ping antes de qualquer TCP/SNMP; sem resposta real, encerra o probe imediatamente.
- Validação do ping Windows exige `TTL=` além do return code, evitando falso positivo de mensagens ICMP de host inalcançável.
- Portas WinRM/SMB/SSH e SNMP só são testadas após o host ser confirmado por ping.
- Hosts sem ping não viram assets descobertos e não recebem credential validation.
- Runner atualizado para 2.17.4 e metadata de pacote sincronizada.

# 5.3.9 - Campaign Runner Binding / No Silent Cycles

- Campaign agora vincula explicitamente um Runner online antes de entrar em `active`.
- Se nenhum Runner estiver elegível, Campaign/Execution ficam em `waiting_runner` com motivo persistido em `stats`.
- Se a fila do Runner estiver pausada, Campaign fica em `waiting_runner` em vez de aparentar execução.
- `campaign_probe` sem Runner deixa de falhar silenciosamente: gera erro explícito no scheduler.
- Primeiro ciclo que não conseguir gerar nenhum path/job é marcado `blocked` com `no_jobs_queued`.
- Scheduler passa a registrar no log cada `campaign_probe` enfileirado com Campaign, Cycle, Runner, Job ID e target.
- Ao recuperar Runner, `next_cycle_at` é normalizado para permitir o primeiro ciclo imediatamente.

# 5.3.8
- Corrige timezone do scheduler da Attack Campaign.
- Campaigns com janela diária configurada no horário local agora são avaliadas no `MAGI_TIMEZONE` (padrão `America/Sao_Paulo`) em vez de UTC.
- Corrige também Resume e cálculo de `next_cycle_at` para usar o mesmo relógio operacional.
- Evita Campaign permanecer sem ciclos quando o backend está em UTC e a janela diária já parece encerrada.

# 5.3.7
- Corrige durable retry spool infinito para resultados de jobs já cancelados/terminais.
- Backend responde ACK terminal com `discard_result=true` em vez de HTTP 400 para retries obsoletos.
- Runner 2.17.3 remove automaticamente resultados antigos do spool após ACK terminal.

# 5.3.6
- Runner Queue Control: limpeza pausa a fila para impedir regeneração imediata por schedulers.
- Deep Inventory periódico respeita queue_paused.
- Configurações > Runners mostra os runner_jobs reais e sua origem.
- Jobs de tipo desconhecido são bloqueados e nunca executados silenciosamente.
- Cancelamento individual de jobs e liberação explícita da fila.

# 5.3.5

- Corrige `RemoteDisconnected` intermitente no polling Runner -> Backend causado por reutilização de sockets HTTP keep-alive encerrados pelo Uvicorn/Docker Desktop.
- Runner passa a enviar `Connection: close`, usando uma conexão HTTP nova por requisição; custo irrelevante no polling local e comportamento mais robusto em Windows + Docker NAT.
- Mantida a serialização da sessão HTTP da 5.3.4.
- Runner atualizado para 2.17.2.

# 5.3.4

- Corrige concorrência HTTP do Runner: polling e heartbeat não acessam mais o mesmo `requests.Session` simultaneamente.
- `reset_session()` agora é serializado com as requisições ativas, evitando fechar/recriar a sessão enquanto outra thread a utiliza.
- Runner atualizado para 2.17.1.
- Correção direcionada ao erro intermitente `RemoteDisconnected('Remote end closed connection without response')`.

# 5.3.3
- Configurações > Runners: nova ação **Limpar Runner** por Runner.
- Cancela todos os `runner_jobs` em `pending/running` do Runner e também jobs `pending` ainda não atribuídos, sem apagar o histórico.
- Sincroniza paths de Campaign vinculados para `cancelled` e evita filas visualmente presas.
- Endpoint administrativo protegido em `/api/settings/runners/{runner_id}/clear`.

# MAGI 4.0 Consolidada

- Consolida 4.0.1–4.0.5 como versão oficial 4.0.
- MAGI Security Checks tornam-se o fluxo principal de Tarefas.
- Atomic Red Team congelado por padrão e reservado para pós-ataque.
- Histórico Atomic anterior permanece disponível.
- Nenhuma nova migration.

# Sprint 4.0.5

- Atomic Remote Execution real via WinRM/PSSession.
- Credencial obrigatória e segredo transitório.
- Target validation.
- Target unreachable/authentication/transport states.
- Prerequisite preparation on remote target.
- Atomic inner exit-code parsing.
- No local fallback for Atomic execution.
- Runner 2.15.0.

## v000.9.0-sprint4.0.3 — Atomic Evidence Engine hardening

- Atomic agora preserva stdout/stderr no retorno do Runner.
- `executed_real_test` passa a refletir a execução real do Atomic.
- Novo estado `executed_unverified` evita tratar exit code 0 como confirmação de efeito.
- Evidência explicita `execution_scope=runner_local` e target solicitado.
- Sem migration de banco.

# Changelog

## v000.9.0-sprint4.0.2 — Unified Validation History

- Histórico unificado de execuções MAGI Security Checks e Atomic Red Team.
- Filtro por origem e identificação explícita do provider.
- Resultado de security checks (`detected`/`not_detected`) visível no histórico.
- Detalhes unificados com evidence e remediation.
- Sem alteração de schema/migration.
## v000.9.0-sprint4.0 — Repository / Planner / Evidence / Remediation
- Novo Repository Engine com providers MAGI, Atomic Red Team e Nuclei (provider Nuclei preparado, não habilitado para execução nesta build).
- Novo catálogo nativo MAGI Security Checks.
- Execution Planner valida target, tarefa, aprovação administrativa e Runner online antes de enfileirar.
- Novo executor `security_check` no Runner.
- Checks defensivos iniciais: RDP/3389, SMB/445, WinRM/5985, WinRM HTTPS/5986, SSH/22 e Telnet/23.
- Evidence Engine persiste estado observado, porta, latência, ponto de observação e resultado do finding.
- Remediation associada a cada check e persistida no histórico.
- Nova área Repositórios dentro de Tarefas, com sincronização, catálogo, planejamento e execução.
- Mantida a política do produto: risco/impacto é metadado; bloqueio de execução ocorre por desabilitação/não aprovação administrativa.

# Sprint 3.2 — 2026-08-10
- Deep Inventory opcional com intervalos de 10, 30 ou 60 minutos.
- Snapshot atual de hardware/sistema sem série histórica de métricas.
- Histórico somente quando há mudança estrutural de hardware.
- Process Knowledge Base e findings persistentes de processos de interesse.
- Runner 2.14.0 com executor `deep_inventory`.
- Migration `20260810_0023`.

# Sprint 3.1 — 2026-08-10
- Credential Engine opcional por scan.
- Cofre de credenciais criptografado no PostgreSQL.
- Runner 2.13.0 com validação Windows WMI/WinRM, SSH e SNMP v2c.
- Máximo de 2 tentativas por host.
- Hostname obtido por credencial preenche ativos sem hostname.
- Segredos não são persistidos em runner_jobs nem artefatos do Runner.


## Sprint 2.3.1 — Enrichment & Asset Compliance
- Pipeline visual e resultado por ativo.
- Novos ativos + inventário consolidado.
- Compliance de nomenclatura para Server, Workstation e Network Device.
- Confidence Engine transparente e evidências persistidas.
- Cleanup por scans ausentes com soft-retire.
- Migration `20260806_0019`.
## 2.11.2 / Sprint 2.1.1
- DNS enrichment opcional via Runner.
- Consulta PTR em DNS primário/secundário configuráveis.
- Fallback para DNS do sistema.
- Persistência de dns_name e hostname_source.


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

## Sprint 2.2 — Asset Intelligence
- Renomeação funcional de Alvos para Ativos.
- Rota `/ativos` com compatibilidade em `/alvos`.
- Inventário com status Detectado, fabricante, origem, Runner e datas de descoberta.
- Pesquisa local e ordenação de colunas.
- Campos `display_name`, `asset_type` e `notes` na tabela `targets`.

## 0.8.8-sprint3.0
- Service Discovery Engine via Runner/Nmap.
- Executor `service_discovery` no Runner 2.12.0.
- Service Knowledge Base.
- Inventário de serviços atuais e histórico de observações.
- Pipeline de scan com etapa de serviços e falhas parciais visíveis.
- Contagem/detalhe de serviços na tela Ativos.

## 0.8.8-sprint3.0.1
- Corrige perfil do Service Discovery para top 1000 e detecção de versão normal.
- Preserva portas abertas desconhecidas e metadados Nmap (OS hint, CPE, tunnel e fingerprint).
- Adiciona artefatos de troubleshooting e teste de regressão do parser.
- Runner 2.12.1; Alembic 20260807_0021.

## Sprint 4.0.1 - migration hotfix
- Corrige falha PostgreSQL/Alembic na migration 0025 causada pelo identificador reservado `references`.
- Mantém o nome lógico/API `references`, usando identificador SQL corretamente delimitado (`"references"`).
- Corrige também o fallback `ensure_validation_schema()` e o UPSERT de `validation_tasks` para impedir recorrência após o startup.

## v000.9.0-sprint5.0 — MAGI Attack Simulator Foundation
- Novo executor Runner `attack_simulation` em safe mode.
- Novo repositório `magi_attack` com 13 simulações iniciais.
- Categorias Endpoint, Active Directory, Network Node e Application.
- Simulações de superfície de movimento lateral para RDP, WinRM, SMB e SSH sem autenticação ou execução remota.
- Canary HTTP/HTTPS para validação de telemetria de WAF/proxy/aplicação.
- Nova API `/api/attack-simulator` e página `/attack-simulator`.
- Histórico reutiliza Evidence Engine existente.
- Atomic permanece congelado para pós-comprometimento; Nuclei continua na trilha de Vulnerability Validation.

## 5.2.0 — Attack Campaign Engine
- Campaign persistente com data/hora inicial e final, janela diária e recorrência opcional.
- Ciclos limitados a 15 minutos e retomada entre dias.
- Até 3 seeds por ciclo e promoção automática de pivots confirmados.
- Política de expansão 10/5/1/0 com limite de jobs outstanding e paths por ciclo.
- Scope CIDR obrigatório e descoberta progressiva sem sair da rede autorizada.
- Inventário básico de ativos encontrados via movimento lateral.
- Histórico por Execution com snapshot final e retenção de 10 snapshots por Campaign.
- Estrutura de dados pronta para o Attack Graph da Build 6.


## 5.2.1 — Alembic migration-chain hotfix
- Corrige a migration `20260826_0026` para apontar para o Revision ID real da migration 0025: `0025_sprint4_repository_planner`.
- Elimina o erro de startup `KeyError: '20260810_0025'` durante `alembic upgrade head`.
- Nenhuma mudança funcional no Attack Campaign Engine 5.2; hotfix restrito à cadeia de migrations e versionamento do pacote.

## 5.3.0 — Multi-Protocol Campaign
- Campaign passa a aceitar credenciais Windows, SSH e SNMP v2c independentes.
- Novos vetores Campaign: WinRM, SMB, SSH e SNMP v2c; RDP não participa da Campaign.
- SMB valida autenticação controlada via IPC$ sem payload remoto.
- SSH valida autenticação e execução benigna de `hostname`.
- SNMP v2c valida community e `sysName.0`, classificado como discovery, nunca como pivot/comprometimento.
- Paths persistem protocolo e tipo de relação (`access`/`discovery`).
- Apenas acesso autenticado promove frontier; discovery SNMP permanece terminal na 5.3.
- Migration 0027 adiciona os campos multi-protocolo preservando dados da 5.2.1.

## 5.3.1
- Attack Campaign: adiciona preflight único por candidato antes do fan-out de autenticação.
- Não promove IP não detectado para Asset.
- WinRM/SMB/SSH somente após service precondition correspondente.
- SNMP v2c pode confirmar discovery no preflight e não gera teste duplicado.
- Classifica runner_dependency_missing, transport_failed e authentication_failed separadamente.
- Configurações existentes do Runner habilitam campaign_probe por migração forward-compatible.

## 5.3.2
- Campaign pause agora cancela fila pendente e paths em andamento.
- Ciclo ativo é encerrado ao pausar.
- Runner queue não entrega jobs pertencentes a Campaign pausada/cancelada/concluída.
- Resultados tardios não sobrescrevem jobs cancelados.
- Delete de Campaign limpa jobs associados antes da remoção.
