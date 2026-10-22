# Test Plan — Sprint 5.2

1. Criar Campaign com 1, 2 e 3 seeds; rejeitar zero ou mais de três.
2. Rejeitar scope vazio, CIDR inválido e bloco individual acima de 4096 endereços.
3. Validar start/end e janela diária.
4. Confirmar que o primeiro ciclo utiliza os seeds manuais.
5. Confirmar que pivots com lateral movement confirmado entram no inventário da Campaign.
6. Confirmar promoção automática de pivots confirmados para seed em ciclos seguintes.
7. Validar política 10/5/1/0 e máximo de 5 jobs outstanding.
8. Confirmar que path origem→destino não se repete na mesma Execution.
9. Confirmar que o ciclo encerra aos 15 minutos e cancela jobs ainda pending.
10. Confirmar pausa fora da janela diária e retomada com frontier persistida.
11. Confirmar snapshot final no término da Execution.
12. Confirmar recorrência N dias após o término e retenção máxima de 10 snapshots por Campaign.
13. Confirmar reconciliação do inventário básico em `targets` após salto confirmado.
14. Regressão: END-101 manual continua retornando `lateral_movement_confirmed` quando A→B funciona.
