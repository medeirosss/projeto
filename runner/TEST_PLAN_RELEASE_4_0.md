# Test Plan — MAGI 4.0 consolidada

1. Subir backend e banco sem nova migration.
2. Abrir Tarefas e confirmar que MAGI Security Checks são o fluxo principal.
3. Executar MAGI-NET-001 em um target conhecido e validar queued/running/success.
4. Abrir Histórico e confirmar registros MAGI.
5. Confirmar que histórico Atomic anterior permanece consultável.
6. Tentar POST de execução Atomic com `ATOMIC_POST_ATTACK_ENABLED=false` e confirmar HTTP 409.
7. Abrir Repositórios e confirmar Atomic como `Congelado / pós-ataque`.
8. Confirmar Nuclei como provider preparado, ainda sem execução nesta release.
