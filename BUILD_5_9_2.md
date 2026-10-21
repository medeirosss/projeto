# MAGI 5.9.2 — Service Monitoring & Verify Now

- Habilitar Monitoring agenda a primeira execução imediatamente (`next_run_at = CURRENT_TIMESTAMP`); scheduler processa em até 60 segundos, sujeito a Runner disponível.
- **Verificar agora** no botão Monitoring: com política habilitada, primeira confirmação inicia verificação manual; cancelar permite acessar a opção de desabilitar.
- Verificação manual não cria jobs sobrepostos e preserva a cadência periódica.
- Serviço: portas TCP previamente conhecidas no campo `inventory.open_ports` ou `inventory.ports` do snapshot. Até 64 portas por host, com scan TCP `-sT -Pn -p` restrito, sem descoberta de portas adicionais.
- Eventos `SERVICE_STATE_CHANGED` somente após duas observações consecutivas de um novo estado em relação a estado anterior conhecido.
- Resultados inconclusivos não geram alteração.
- Tabela `security_monitor_service_checks` criada pelo bootstrap do Monitoring. Nenhuma migração destrutiva.
- Testar com Runner Windows e PostgreSQL real; verificações de sintaxe não substituem homologação integrada.

**Atenção:** se o baseline não contiver `inventory.open_ports` ou `inventory.ports`, o monitoramento de serviços não produzirá jobs. O monitoramento de hosts permanece ativo. A interface completa de eventos está reservada à Build 6.
