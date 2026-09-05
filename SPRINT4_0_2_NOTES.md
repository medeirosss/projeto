# MAGI Sprint 4.0.2

Hotfix de integração do histórico de validações.

## Alterações

- Histórico de Tarefas passa a consumir `/api/repositories/executions`.
- Atomic Red Team e MAGI Security Checks são normalizados em uma única resposta.
- Nova coluna `Origem` diferencia MAGI e Atomic Red Team.
- Nova coluna `Resultado` exibe `detected`, `not_detected`, erro ou estado pendente para checks MAGI.
- Filtro por origem (`MAGI` / `Atomic Red Team`).
- Campo Técnica agora também aceita `MAGI-NET-*`.
- Detalhes de execução passam a usar `/api/repositories/executions/{source}/{id}`.
- Security checks preservam evidência, remediation, finding_status e finding_message.
- Nenhuma nova migration é necessária.

## Compatibilidade

O endpoint Atomic anterior continua disponível. A mudança afeta apenas a visão unificada do Histórico.
