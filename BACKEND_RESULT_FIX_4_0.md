# MAGI 4.0 — Backend Result/Retry Fix

Correção complementar da camada Target Reachability.

## Backend
`target_unreachable` passa a ser um status terminal válido do Runner.

Isso permite concluir uma execução com:
- `status = target_unreachable`
- `finding_status = not_evaluated`
- `confirmation_status = target_unreachable`

## Runner — entrega confiável de resultados
Executar um job e entregar seu resultado ao backend passam a ser estados separados.

Se `POST /api/runners/jobs/{id}/result` falhar:
1. o resultado completo é persistido em `state.json` / `failed_result_spool`;
2. o job não é marcado como `completed_jobs`;
3. o Runner tenta entregar o spool novamente nas iterações seguintes;
4. apenas após HTTP de sucesso o item sai do spool e o job é marcado como concluído localmente.

Isso evita resultados perdidos e jobs presos em `running` após falhas de API/rede.
