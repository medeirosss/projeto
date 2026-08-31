# MAGI Sprint 5.3.3

## Limpeza administrativa do Runner

Em **Configurações > Runners**, cada Runner possui agora a ação **Limpar Runner**. A operação não apaga histórico: jobs ainda `pending` ou `running` são marcados como `cancelled`, recebem `finished_at` e motivo administrativo. Paths de Campaign vinculados também são cancelados para impedir estados presos em `queued/running`. Jobs já finalizados permanecem intactos. Como a arquitetura atual opera com Runner único, jobs `pending` ainda sem `runner_id` também são cancelados para impedir que sejam puxados imediatamente após a limpeza.
