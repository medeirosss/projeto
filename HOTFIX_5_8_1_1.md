# MAGI 5.8.1 Hotfix 1 — Nova execução

- Botão **Nova execução** para Campaign com última execução concluída/cancelada.
- `POST /api/attack-simulator/campaigns/{campaign_uuid}/new-execution`.
- Cria uma nova linha em `attack_campaign_executions` com `execution_number` incremental e janela de duração igual à anterior, iniciando no horário atual da Campaign.
- Mantém `campaign_id`, configurações, histórico, baselines e diffs existentes.
- Bloqueia reinício quando a última execução ainda está ativa, pausada ou agendada; exige Campaign habilitada.
- Sem migração de banco necessária.

## Homologação
1. Encerrar uma Campaign pelo botão existente e confirmar baseline.
2. Clicar em Nova execução; conferir incremento do número e novo execution_id.
3. Conferir que o Runner inicia novos ciclos sem reutilizar o estado operacional anterior.
4. Encerrar a segunda execução e confirmar o diff contra o baseline anterior.
5. Tentar criar outra execução enquanto a atual estiver aberta: API deve rejeitar.
6. Validar que os registros históricos anteriores continuam disponíveis.

Não foram realizados testes de integração com PostgreSQL ou Runner Windows neste ambiente.
