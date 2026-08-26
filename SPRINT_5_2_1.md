# MAGI Sprint 5.2.1 — Alembic Migration Chain Hotfix

## Objetivo
Corrigir o defeito de instalação identificado na Build 5.2.0, no qual a migration `20260826_0026_attack_campaign_engine_5_2.py` referenciava um Revision ID inexistente (`20260810_0025`).

## Causa raiz
A migration anterior está no arquivo `20260810_0025_sprint4_repository_planner.py`, porém seu Revision ID real é `0025_sprint4_repository_planner`. O Alembic resolve dependências pelo `revision`, não pelo nome do arquivo.

## Correção
A migration 0026 passa a declarar:

```python
revision = "20260826_0026"
down_revision = "0025_sprint4_repository_planner"
```

## Escopo
Este release não altera a lógica funcional da Build 5.2.0. Attack Campaign Engine, Runner, frontend e APIs permanecem funcionalmente iguais.
