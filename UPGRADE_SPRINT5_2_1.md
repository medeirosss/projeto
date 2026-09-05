# Upgrade — MAGI Sprint 5.2.1

Esta build substitui a 5.2.0 e corrige somente a cadeia Alembic.

## Procedimento
1. Pare os containers atuais.
2. Substitua os arquivos da aplicação pelos da Build 5.2.1, preservando seu `.env` e volume PostgreSQL.
3. Execute `docker compose build --no-cache`.
4. Execute `docker compose up`.
5. Verifique no log que `alembic upgrade head` conclui sem `KeyError: '20260810_0025'`.

Não é necessário apagar o banco para este hotfix. Se a 5.2.0 falhou antes de aplicar a migration 0026, o banco existente pode ser preservado.
