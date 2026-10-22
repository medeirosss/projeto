# Upgrade — MAGI 5.3

Base suportada: 5.2.1.

- Preserve o volume PostgreSQL.
- Substitua os arquivos da aplicação/Runner pela Build 5.3.
- Rebuild recomendado: `docker compose build --no-cache`.
- Inicie com `docker compose up` e confirme a migration `20260826_0026 -> 20260829_0027`.
- Atualize o Runner com os arquivos da pasta `runner`; SSH requer `paramiko` presente conforme requirements do Runner.
- Cadastre SSH/SNMP em Configurações > Credenciais antes de habilitar esses vetores na Campaign.

Rollback de aplicação para 5.2.1 não deve ser feito mantendo o schema 0027 sem planejamento. Faça backup do banco antes do upgrade em ambientes não descartáveis.
