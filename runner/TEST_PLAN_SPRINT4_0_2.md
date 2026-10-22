# Test Plan — Sprint 4.0.2

1. Subir backend mantendo o volume PostgreSQL existente.
2. Confirmar Runner online em Configurações > Runners.
3. Executar `MAGI-NET-001` em um alvo conhecido.
4. Abrir Tarefas > Histórico e confirmar uma linha com Origem `MAGI` e o mesmo Runner Job ID.
5. Aguardar conclusão e atualizar o histórico; validar `success` e Resultado `DETECTADO` ou `NÃO DETECTADO`.
6. Abrir Detalhes e validar evidence, remediation, started_at e finished_at.
7. Executar uma técnica Atomic e confirmar que ela aparece na mesma tabela com Origem `Atomic Red Team`.
8. Testar filtros por Origem, Status, Runner e Técnica/Check.
