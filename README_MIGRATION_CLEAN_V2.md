# Centric v2 - baseline limpa pós-migração

Esta versão consolida a migração principal para PostgreSQL.

## Fonte oficial dos dados

Agora o PostgreSQL é a fonte oficial para:

- Configurações
- Credenciais
- Scripts/Playbooks
- Execuções
- Alertas
- Histórico de alertas
- Relatórios e scans
- Uploads CSV de comparação
- Autenticação local/roles
- Licenciamento/status

## O que continua em arquivo

Por decisão de arquitetura, continuam fora do banco:

- Logs operacionais em `backend/logs`
- Arquivo de licença em `/app/license/license.json`
- Chave pública de validação da licença
- Assets estáticos do frontend
- Scripts materializados temporariamente em `scripts/.runtime` durante execução

## Removido como fonte oficial

Os arquivos abaixo não são mais usados como fonte oficial:

- `backend/data/settings.json`
- `backend/data/action_credentials.json`
- `backend/data/alerts_db.json`
- `backend/data/inbound_alerts.json`
- `backend/json/ad_computers.json`
- `backend/json/endpointcentral_computers.json`
- CSVs fixos na pasta `compare`
- `scripts/_last_alert.json`

## Observação sobre playbooks

Scripts cadastrados pela interface são armazenados na tabela `playbooks`.
Durante a execução, o backend materializa temporariamente o conteúdo em `scripts/.runtime` apenas para execução local.

## Observação sobre logs

Logs não foram migrados para o banco por decisão do projeto.
