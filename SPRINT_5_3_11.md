# MAGI Sprint 5.3.11 — Campaign Multi-Cycle Continuation

## Problema corrigido
A Campaign executava o primeiro ciclo normalmente, mas após o intervalo configurado não iniciava um segundo ciclo quando nenhum host tinha obtido `access_confirmed`.

A causa era `_select_cycle_seeds()`: a partir do segundo ciclo, os seeds iniciais eram descartados e somente assets com `access_confirmed=TRUE` podiam iniciar o ciclo seguinte. Sem credencial confirmada, a lista de seeds ficava vazia e a execução era encerrada incorretamente como `scope_exhausted`.

## Nova regra
- Os `initial_seeds` permanecem como origens de descoberta nos ciclos seguintes enquanto ainda houver candidatos não testados no escopo.
- Cada ciclo continua respeitando `cycle_interval_minutes` e a política de branches.
- `_candidate_for_origin()` continua usando o histórico da execução, portanto um novo ciclo segue para os próximos IPs em vez de repetir os mesmos caminhos.
- Hosts com acesso confirmado continuam podendo ser adicionados como novas origens para progressão lateral.
- `scope_exhausted` só ocorre quando nenhuma origem elegível possui mais candidatos distintos para avaliar.

## Exemplo esperado
Com `branch_policy[0] = 10` e uma rede /24:
- ciclo 1: seed A avalia até 10 candidatos;
- após 15 min: ciclo 2 continua com os próximos candidatos ainda não testados;
- ciclos posteriores continuam da mesma forma;
- a execução termina apenas quando o escopo/caminhos possíveis forem realmente esgotados ou a janela da Campaign terminar.
