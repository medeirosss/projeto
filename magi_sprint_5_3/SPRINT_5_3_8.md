# MAGI Sprint 5.3.8 — Campaign Timezone Fix

## Problema
A Campaign armazenava `start_at`, `daily_start` e `daily_end` como horários de parede (sem timezone), mas o scheduler comparava esses campos com `datetime.utcnow()`. Em instalações no Brasil, uma Campaign 08:00–18:00 era avaliada como encerrada depois das 15:00 locais.

## Correção
- Adicionado relógio operacional `_campaign_now()`.
- Timezone definido por `MAGI_TIMEZONE` ou `TZ`; padrão `America/Sao_Paulo`.
- `process_campaigns_once`, `campaign_resume` e o cálculo de `next_cycle_at` usam o mesmo horário local.

## Critério de aceite
Uma Campaign iniciada às 16:35 com janela 08:00–18:00 em America/Sao_Paulo deve criar imediatamente o primeiro ciclo e gerar paths/jobs elegíveis.
