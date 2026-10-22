# Magi - Atomic Red Team Step 1

Esta etapa adiciona somente o catálogo/importador do Atomic Red Team.

## O que foi alterado

- Backend:
  - `backend/app/routers/validations.py`
  - `backend/app/services/atomic_service.py`
  - `backend/app/repositories/atomic_repository.py`
  - inclusão do router em `backend/main.py`
- Frontend:
  - `/validacoes`
  - `frontend/validations.html`
  - `frontend/validations.js`
  - item `Validações` no menu
- Banco:
  - migration Alembic `20260527_0009_atomic_validation_catalog.py`
  - tabelas `atomic_import_runs`, `atomic_techniques`, `atomic_tests`
- Docker Compose:
  - preserva o Postgres já existente do Magi
  - adiciona somente o volume read-only `./atomic-red-team:/opt/atomic-red-team:ro`
  - adiciona `ATOMIC_RED_TEAM_PATH=/opt/atomic-red-team/atomics`

## Como usar

1. Extraia o repositório Atomic Red Team na raiz do projeto com o nome:

```text
atomic-red-team
```

2. Suba o ambiente:

```bash
docker compose up -d --build
```

3. Acesse:

```text
/validacoes
```

4. Clique em **Importar catálogo**.

## Observação de segurança

Esta etapa não executa testes Atomic. Ela apenas lê os YAMLs e importa o catálogo para o banco do Magi.
