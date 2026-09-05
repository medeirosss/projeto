# Upgrade — Sprint 2.3.1

- Novo Alembic head: `20260806_0019`.
- Não há alteração obrigatória no Runner nesta sprint; mantenha o Runner funcional usado na Sprint 2.3.
- O cleanup vem desabilitado por padrão e exige no mínimo 3 scans ausentes.
- A exclusão/cleanup do inventário é lógica: tarefas, evidências e auditoria permanecem vinculadas ao `target_uuid`.
- Após o deploy, execute um novo scan para gerar os primeiros `enrichment_events` e as evidências de confiança.
