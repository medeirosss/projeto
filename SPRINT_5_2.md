# MAGI Sprint 5.2 — Attack Campaign Engine

## Objetivo
A Build 5.2 transforma o movimento lateral validado na 5.1.2 em uma Campaign persistente, limitada e retomável. O Attack Graph visual permanece reservado para a Build 6; esta versão prepara os dados que o Graph consumirá.

## Modelo de Campaign
- 1 a 3 Hosts A iniciais (seeds).
- Scope CIDR obrigatório; blocos individuais limitados a 4096 endereços na 5.2.
- Data/hora de início e data/hora de término por Execution.
- Janela diária configurável (ex.: 08:00–18:00). Fora dela a Campaign pausa sem perder estado.
- Ciclos de 15 minutos. O ciclo não inicia quando não há tempo suficiente na janela diária.
- Política de expansão do círculo: `10 → 5 → 1 → 0`.
- Até 5 jobs pendentes/running simultaneamente por Campaign Cycle e até 60 paths por ciclo.
- O END-101 validado na 5.1.2 continua sendo o motor de cada aresta: origem autentica, cria/verifica/remove evidência, e inicia o salto WinRM para o destino.

## Mudança automática de Host A
A Campaign mantém ativos confirmados e `seed_count`. No primeiro ciclo usa os seeds manuais. Nos ciclos seguintes seleciona até três pivots confirmados com menor número de usos como seed. Assim, hosts B/C confirmados migram naturalmente para Host A de novos círculos sem o técnico ter que promovê-los manualmente.

## Descoberta progressiva
Para cada origem, a 5.2 prioriza IPs que já existem no inventário MAGI dentro do scope e depois percorre endereços ainda não avaliados no CIDR. Paths já avaliados para a mesma origem não são repetidos durante a mesma Execution. Um mesmo destino ainda pode ser validado por outra origem porque `A → B` e `C → B` representam caminhos de segurança distintos.

## Inventário básico por Attack Campaign
Quando um salto é confirmado, o MAGI registra o IP/hostname retornado pelo endpoint, protocolo utilizado e caminho que originou o acesso. O ativo também é reconciliado com `targets` usando `discovery_source=attack_campaign`.

## Ciclo de vida
`scheduled → active ↔ daily pause → completed`.
A Execution termina por data/hora final ou por esgotamento da frontier. Uma Campaign recorrente pode criar uma nova Execution N dias após o término da anterior.

## Histórico
Cada Campaign guarda no máximo 10 Executions/Snapshots finais. Ao concluir uma Execution, o snapshot compacta ativos, paths, estados e evidências finais. Ao entrar a 11ª, a mais antiga é excluída daquela Campaign.

## Build 6
A Build 6 consumirá `campaign executions`, `cycles`, `assets` e `paths` para o primeiro Attack Graph visual e comparação entre snapshots. Nenhuma dependência de UI gráfica foi colocada no motor 5.2.
