# Sprint 3.0.1 — Service Discovery correction

Correção baseada em XML real do Nmap 7.99.

- Perfil padrão alterado de top 100 + `--version-light` para top 1000 + detecção normal (`-sV`).
- Toda porta `open` é mantida, inclusive serviço `unknown`.
- Parser preserva `ostype`, CPE, `servicefp`, tunnel, method e confidence.
- Service Knowledge Base continua sendo enriquecimento; nunca filtra portas desconhecidas.
- Artefatos locais do Runner incluem comando, stdout XML e JSON normalizado.
- Runner 2.12.1.
- Alembic head: `20260807_0021`.
