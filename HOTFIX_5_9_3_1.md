# MAGI 5.9.3 Hotfix 1 — Service Alert Policies

- Configuração por ativo e serviço TCP em Ativos Analisados > Serviços.
- Política padrão: enabled=true, condition=unavailable, polls=2, cooldown_minutes=60, severity=warning.
- Avaliação em observações de Monitoring concluídas, uma vez por execução; resultados inconclusivos não contam.
- Histórico persistido em security_service_alerts, com reconhecimento, encerramento e repetição controlada.
- Central de Alertas apresenta seção de alertas de serviços, sem substituir os alertas legados.
- Novas tabelas criadas de forma idempotente pelo ensure_monitoring_schema.

## Limitações
- O Monitoring Light executa verificações de serviços apenas para IPs presentes no baseline de Campaign ativo. A política salva em um ativo fora desse escopo aguardará monitoramento compatível.
- O estado `closed` precisa ser reportado explicitamente pelo Runner; timeouts são inconclusivos.
- A opção `both` monitora transições, não indisponibilidade contínua.
- Não foram executados testes de integração com PostgreSQL/Runner Windows.
