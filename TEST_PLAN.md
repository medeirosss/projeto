# Plano de Testes — Sprint 1 Validation History

## Objetivo
Validar que o histórico de validações Atomic está pesquisável, auditável e compatível com o fluxo atual de execução via Runner.

## Testes mínimos

### 1. Subida da aplicação
1. Executar `docker compose up -d --build`.
2. Abrir `/validations`.
3. Confirmar que a página carrega sem erro no console do navegador.

Resultado esperado: tela de Validações abre e lista catálogo/histórico.

### 2. Histórico sem filtros
1. Abrir Validações.
2. Clicar em `Atualizar histórico`.

Resultado esperado: tabela mostra até 50 execuções recentes e contador total.

### 3. Filtro por técnica
1. Informar uma técnica, por exemplo `T1059`.
2. Aguardar atualização automática.

Resultado esperado: tabela mostra apenas execuções daquela técnica.

### 4. Filtro por runner
1. Informar um `Runner ID` conhecido.

Resultado esperado: tabela mostra somente execuções daquele runner.

### 5. Filtro por status
1. Selecionar `success`, `failed`, `timeout`, `queued` ou outro status disponível.

Resultado esperado: tabela mostra apenas execuções com o status selecionado.

### 6. Filtro por período
1. Informar data inicial e/ou data final.

Resultado esperado: tabela respeita o intervalo informado usando `created_at`.

### 7. Detalhe da execução
1. Clicar em `Detalhes` em qualquer execução.

Resultado esperado: o painel de resultado exibe UUID, técnica, atomic test number, status, runner, timestamps, duração, stdout, stderr, exit code, evidence e payload.

### 8. Fluxo existente de execução LAB
1. Aprovar um teste.
2. Informar Runner ID.
3. Executar LAB.
4. Atualizar histórico.

Resultado esperado: execução aparece no histórico com status inicial `queued` e, após retorno do Runner, com status final e evidências.

## Critério de aprovação da sprint
A sprint é aprovada quando o histórico permitir consultar execuções por técnica, runner, status, solicitante e período, e quando o detalhe da execução apresentar evidência suficiente para auditoria operacional.
