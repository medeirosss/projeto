# Test Plan — MAGI Sprint 5.2.1

## 1. Validação da árvore Alembic
1. Executar `alembic heads`.
2. Confirmar que `20260826_0026` aparece como head.
3. Executar `alembic history` e confirmar a sequência `20260810_0024 -> 0025_sprint4_repository_planner -> 20260826_0026`.

## 2. Upgrade em base existente
1. Usar banco proveniente da build anterior.
2. Executar `docker compose up --build`.
3. Confirmar ausência de `KeyError: '20260810_0025'`.
4. Confirmar que o backend permanece em execução após as migrations.

## 3. Banco novo
1. Em ambiente de teste descartável, remover volumes do PostgreSQL.
2. Subir o compose novamente.
3. Confirmar execução completa das migrations e startup do backend.

## 4. Regressão funcional
1. Efetuar login.
2. Abrir Attack Simulator.
3. Confirmar carregamento das Campaigns.
4. Criar uma Campaign de teste dentro de um scope autorizado.
5. Confirmar persistência e leitura sem erro 5xx.
