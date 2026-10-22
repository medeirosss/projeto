# Upgrade — Sprint 3.2

- Backup do PostgreSQL recomendado antes do upgrade.
- O container executará Alembic até `20260810_0023`.
- Atualize o Runner para 2.14.0. O `allowed_executors` é migrado em memória para incluir `deep_inventory` quando `credential_validate` já estiver habilitado.
- Nmap continua sendo dependência manual do Runner para Discovery/Service Discovery; Deep Inventory não adiciona dependências Windows além das já existentes.
