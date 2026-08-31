# MAGI Sprint 4.0.1 - Hotfix da migration 0025

## Problema
A Sprint 4.0 original usava `references` como nome de coluna sem delimitador SQL em `validation_tasks`. Em PostgreSQL, `REFERENCES` faz parte da gramática de constraints e a migration falhava antes do backend iniciar.

## Correção
O schema mantém a coluna lógica `references`, mas todas as instruções DDL/DML passam a usar `"references"`.
Foram corrigidos:
- `alembic/versions/20260810_0025_sprint4_repository_planner.py`
- `backend/app/repositories/validation_repository.py`

## Upgrade
Não é necessário apagar o volume PostgreSQL nem voltar para a Sprint 3.3. A migration anterior falhou dentro da transação e pode ser executada novamente com esta build.
