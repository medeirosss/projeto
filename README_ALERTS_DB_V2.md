# Centric v2 - Alertas em PostgreSQL

Esta versão migra o módulo de Alertas para PostgreSQL.

## Mudanças principais

- `alerts_db.json` deixa de ser fonte oficial.
- `inbound_alerts.json` deixa de ser fonte oficial.
- `scripts/_last_alert.json` deixa de ser fonte oficial.
- Alertas recebidos pelo endpoint `/api/actions/inbound-alert` são gravados na tabela `alerts`.
- Alterações de status são gravadas na tabela `alert_history`.
- A tela `/alertas` lê alertas ativos/resolvidos diretamente do banco.
- A tela `Ações > Executar playbook por alerta` lê alertas ativos diretamente do banco.
- Execuções por alerta passam a registrar o vínculo com `alerts.id` quando o alerta existe no banco.

## Tabelas utilizadas

- `alerts`
- `alert_history`
- `playbook_executions`

## Status de alertas

- `1` = novo alarme
- `2` = conhecido
- `3` = finalizado

## Teste limpo

```bash
docker compose down -v
docker compose up --build -d
docker compose logs -f app
```

## Teste de alerta inbound

```bash
curl -X POST http://localhost:8443/api/actions/inbound-alert \
  -H "Content-Type: application/json" \
  -d '{
    "source_system": "ADAuditPlus",
    "event_number": "4720",
    "display_name": "User Account Created",
    "username": "teste.user",
    "mitre_tactic": "Persistence",
    "mitre_technique": "T1136.002",
    "nist_control": "AC-2",
    "severity": "Alta",
    "source_ip": "192.168.0.10"
  }'
```

Depois consulte:

```bash
curl http://localhost:8443/api/alerts
```
