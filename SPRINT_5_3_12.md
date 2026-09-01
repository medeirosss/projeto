# MAGI Sprint 5.3.12 — Campaign Stateful / Release Candidate

## Objetivo
Fechar a Build 5.3 com uma Campaign stateful, controlável e capaz de avançar por ciclos e saltos sem repetir trabalho desnecessário.

## Alterações
- Política de ramificação consolidada em `10 / 5 / 3 / 0`.
- Histórico por execução: um IP já avaliado como target não é procurado novamente.
- Hosts com `access_confirmed` continuam elegíveis como seed/origem futura.
- Cycle tem duração máxima de 15 minutos.
- Se todos os jobs retornarem antes do limite e não houver mais trabalho naquele cycle, ele é finalizado imediatamente e o próximo fica elegível sem espera artificial.
- `Ajustar`: PATCH da Campaign existente, preservando executions, assets e paths.
- `Próximo ciclo agora`: encerra/cancela trabalho pendente do cycle atual e torna o próximo cycle imediatamente elegível.
- `Excluir`: disponível na UI e cancela trabalho pendente antes da remoção da Campaign.
- `Pausar/Retomar` mantidos.
- SNMP v2c permanece discovery-only: pode identificar equipamento/hostname, mas não cria pivot.
- SSH permanece vetor de acesso e, quando autenticado, pode gerar novo seed.

## Critério de fechamento da 5.3
Validar em ambiente real:
1. Windows via SMB/WinRM.
2. Linux via SSH.
3. Equipamento de rede via SNMP v2c sem pivot.
4. Múltiplos cycles automáticos.
5. Reuso apenas de hosts acessados como seeds, sem reprobe de IP já avaliado.
6. Controles Ajustar, Próximo ciclo agora, Pausar/Retomar e Excluir.
7. Nenhum job sem origem/rastreabilidade no Runner.
