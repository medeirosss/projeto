# Centric v2 — Execuções de Playbook em PostgreSQL

Esta versão passa a registrar as execuções de playbooks no PostgreSQL, usando a tabela `playbook_executions`.

## O que foi migrado

- Execução manual registra início/fim/status no banco.
- Execução por alerta registra início/fim/status no banco.
- O usuário autenticado é salvo em `executed_by`.
- Saída do script é salva em `output`.
- Erro/STDERR é salvo em `error`.
- O frontend possui a nova opção em **Ações > Histórico de execuções**.

## Endpoint novo

```text
GET /api/actions/executions?limit=100
```

## Tabela usada

```text
playbook_executions
```

## Observação

A tabela de alertas ainda será migrada em etapa própria. Nesta fase, a execução por alerta já fica persistida no banco, mas o vínculo formal via `alert_id` será consolidado quando o módulo de Alertas for migrado para PostgreSQL.
