# MAGI Sprint 4.0.3

## Atomic Evidence Engine hardening

Esta release corrige a semântica de evidência das execuções Atomic Red Team.

- O Runner passa a devolver `stdout` e `stderr` no resultado enviado ao backend.
- Execuções reais Atomic passam a registrar `executed_real_test=true`.
- O histórico diferencia `confirmed`, `not_confirmed`, `executed_unverified` e `error`.
- Nesta release, Atomic sem verificador pós-execução é classificado como `executed_unverified`; `exit_code=0` não é tratado como confirmação do efeito.
- A evidência registra `execution_scope=runner_local` e `requested_target`, deixando explícito que o transporte Atomic atual executa no host do Runner.
- Nenhuma migration de banco é necessária.
