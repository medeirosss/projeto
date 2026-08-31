# Sprint 5.3.7 — Terminal Result Acknowledgement

## Problema corrigido
Jobs cancelados ou removidos no backend podiam permanecer indefinidamente no `failed_result_spool` local do Runner. O backend rejeitava o resultado com HTTP 400 e o Runner interpretava qualquer 400 como falha temporária, reenviando a cada ciclo.

## Alterações
- Backend passa a reconhecer retries de resultado para jobs já terminais (`cancelled`, `blocked`, `success`, `failed`, `error`, `timeout`, `target_unreachable`, `completed`).
- Para esses casos o endpoint de resultado responde HTTP 200 com `discard_result=true`, preservando o estado terminal do job sem reprocessar o resultado.
- Jobs que já não existem no backend também recebem confirmação terminal `job_not_found`, evitando retry infinito de spool obsoleto.
- Runner 2.17.3 interpreta a confirmação terminal como ACK administrativo, remove imediatamente o item do durable retry spool e registra a limpeza no log.
- O comportamento vale tanto para resultados antigos já no spool quanto para um job que seja cancelado enquanto ainda está terminando localmente.

## Resultado esperado
Após atualizar backend e Runner, entradas antigas como jobs 715 e 749 são tentadas uma única vez, recebem confirmação terminal do backend e desaparecem do retry spool local.
