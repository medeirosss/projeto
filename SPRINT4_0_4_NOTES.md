# MAGI Sprint 4.0.4

Fechamento do Evidence Engine Atomic.

- `prevented`: evidência capturada contém sinal explícito de prevenção/interferência de segurança.
- `not_confirmed`: execução ocorreu, mas o output contém erro interno conhecido e o efeito não foi comprovado.
- `executed_unverified`: execução real sem confirmação independente.
- `confirmed`: reservado para verificadores pós-execução específicos.
- `error`: falha/timeout do Runner.
- `exit_code=0` nunca é tratado sozinho como confirmação.
- Mantém `execution_scope=runner_local` para não atribuir Atomic local ao target remoto.
- Melhora decodificação do PowerShell no Windows pt-BR (CP850).
