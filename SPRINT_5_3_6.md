# MAGI Sprint 5.3.6 — Runner Queue Control

## Objetivo
Nenhum job pode rodar sem ser visível e controlável no MAGI.

## Mudanças
- **Limpar Runner** agora também coloca a fila administrativa do Runner em **PAUSADA**. Isso impede que produtores periódicos, especialmente Deep Inventory, voltem a alimentar a fila logo após a limpeza.
- Deep Inventory periódico respeita a pausa da fila e não cria novos jobs enquanto ela estiver pausada.
- Novo botão **Liberar fila** para retomada explícita.
- Nova tabela **Jobs do Runner** em Configurações > Runners, mostrando ID real de `runner_jobs`, origem, executor, target, status e ação de cancelamento.
- Tipos de job desconhecidos são marcados como `blocked`/`uncontrolled_job` e nunca são entregues ao Runner.
- Cancelamento individual sincroniza as tabelas espelho conhecidas.
- Histórico de jobs concluídos/falhos/cancelados é preservado.

## Regra de aceite
Se o Runner registrar `Executing job N`, o job N deve ser localizável na interface do MAGI. Jobs de tipo não reconhecido ficam bloqueados e visíveis para investigação.

## Nota sobre spool
Resultados locais já executados antes de uma limpeza ainda podem existir no retry spool do Runner. O backend continua recusando sobrescrever jobs cancelados. A limpeza física/cooperativa do spool será tratada separadamente porque o backend não possui acesso direto ao filesystem do Runner.
