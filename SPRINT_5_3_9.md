# Sprint 5.3.9 — Campaign Runner Binding

Objetivo: eliminar o estado silencioso em que a Campaign aparece ativa sem criar paths/jobs para o Runner.

## Regras
1. `active` só é permitido com Runner online e fila liberada.
2. Sem Runner: `waiting_runner`, com `scheduler_reason`.
3. Fila pausada: `waiting_runner`, sem iniciar ciclo.
4. Ciclo criado sem nenhum path/job: `blocked / no_jobs_queued`.
5. Todo `campaign_probe` enfileirado gera linha de observabilidade no backend contendo campaign/cycle/job/runner/target.

## Aceite
Ao iniciar uma Campaign válida dentro da janela diária, deve ocorrer uma destas duas saídas observáveis em poucos ciclos do scheduler:
- `campaign_probe` criado e entregue ao Runner; ou
- Campaign explicitamente `waiting_runner`/`blocked` com motivo.
Nunca permanecer `active` sem path/job e sem diagnóstico.
