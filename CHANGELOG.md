# Changelog

## 0.8.0-validation-history

### Added
- Histórico de validações Atomic com filtros por texto livre, técnica, runner, status, solicitante e período.
- Contagem total de registros no endpoint `/api/validations/atomic/executions`.
- Campo `duration_seconds` no retorno de histórico e detalhe de execução.
- Botão de detalhes por execução no frontend, exibindo payload, evidência, stdout, stderr, exit code, runner e UUID.
- Documento `ROADMAP.md` como escopo oficial até a Golden Image 1.0.
- Documento `TEST_PLAN.md` com critérios de validação da sprint.
- Documento `UPGRADE.md` com instruções de atualização.
- Arquivo `VERSION` para controle de release.

### Changed
- A área de execuções da tela de validações foi reposicionada como histórico operacional, não apenas lista de previews.
- O endpoint de execuções continua retrocompatível, mas agora aceita filtros opcionais.

### Notas
- Não há migration obrigatória nesta sprint.
- A regra de produto permanece: o Magi não bloqueia por risco, reboot, dependência ou plataforma; o bloqueio real é aprovação/admin ou teste desabilitado.
