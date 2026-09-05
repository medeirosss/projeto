# Magi Atomic Red Team — Etapa 3B

Esta etapa adiciona o despacho controlado de validações Atomic para Runner.

## O que foi adicionado

- Endpoint para enviar preview aprovado ao Runner:
  - `POST /api/validations/atomic/executions/{execution_id}/dispatch`
- Job type novo:
  - `atomic_validation`
- Atualização automática da tabela `atomic_execution_jobs` quando o Runner devolve resultado.
- Runner de referência:
  - `runner/magi_atomic_runner_reference.py`

## Segurança operacional

Nesta etapa, o Runner de referência vem em **dry-run por padrão**. Ele valida o ciclo completo:

```text
Magi -> fila runner_jobs -> Runner -> resultado -> atomic_execution_jobs
```

Ele não executa teste real do Atomic Red Team.

## Como testar

1. Aprovar um teste Atomic na tela Validações.
2. Clicar em **Preparar**.
3. Informar um Runner ID, por exemplo:

```text
runner-lab-01
```

4. Clicar em **Enviar ao Runner**.
5. Rodar o Runner de referência fora do container ou em uma máquina de laboratório:

```bash
pip install requests
set MAGI_API_URL=http://localhost:8000
set MAGI_RUNNER_ID=runner-lab-01
python runner/magi_atomic_runner_reference.py
```

No Linux:

```bash
pip install requests
export MAGI_API_URL=http://localhost:8000
export MAGI_RUNNER_ID=runner-lab-01
python3 runner/magi_atomic_runner_reference.py
```

6. Atualizar a tela Validações e confirmar status `success`.

## Próxima etapa

3C deve implementar execução real somente em laboratório, com:

- allowlist local;
- apenas `ShowDetailsBrief` primeiro;
- controle por grupo de Runner;
- trava para técnicas sensíveis;
- auditoria completa.
