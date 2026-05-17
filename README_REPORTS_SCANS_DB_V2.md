# Reports/Scans em PostgreSQL - v2

Esta versão migra a fonte oficial de dados de **Relatórios** e **Scans** para PostgreSQL.

## O que foi migrado

- Último scan do Active Directory para `scan_snapshots`.
- Último scan do Endpoint Central/UEM para `scan_snapshots`.
- CSVs enviados para comparação para `report_files`.
- Resultados de comparação AD x UEM x CSV para `scan_compare_runs`.
- Relatório de usuários ativos passa a ler o último snapshot UEM no banco.
- Dashboard passa a calcular AD x UEM com os snapshots do banco.

## O que NÃO foi migrado

Logs operacionais continuam em arquivo, conforme decisão do projeto:

- `backend/logs/`
- logs de API/token/debug
- logs de execução técnica

## Tabelas adicionadas

```sql
scan_snapshots
report_files
scan_compare_runs
```

## Regra da v2 limpa

A fonte oficial de dados para relatórios e scans agora é o PostgreSQL.
Arquivos antigos como `ad_computers.json`, `endpointcentral_computers.json` e CSVs da pasta `compare` não são mais usados como fonte oficial.

## Observação sobre exportação

A exportação CSV é gerada em memória e entregue para download. Ela não grava mais `scan_compare_result.csv` como arquivo oficial.
