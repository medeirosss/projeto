# Test Plan - Sprint 4.0.3

1. Execute um Atomic aprovado.
2. Confirme no Histórico que `executed_real_test` é `true`.
3. Confirme que STDOUT/STDERR aparecem no detalhe quando produzidos pelo comando.
4. Para Atomic sem verificador dedicado, confirme Resultado = `EXECUTADO / NÃO VERIFICADO`.
5. Confirme na evidência `execution_scope=runner_local` e `requested_target=<target informado>`.
6. Confirme que falha/timeout aparece como `ERRO`.
7. Execute um MAGI security_check e confirme que o comportamento `DETECTADO/NÃO DETECTADO` permanece inalterado.
