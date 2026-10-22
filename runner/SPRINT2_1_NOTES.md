# Sprint 2.1 — Asset Intelligence / Discovery Enrichment

## Entregue
- Parser Nmap do Runner preserva `hostname`, `vendor`, `status`, IP e MAC.
- O Runner permite resolução de nomes pelo Nmap (remoção de `-n`).
- Targets registram `vendor`, `dns_name`, `status`, `last_scan_id` e `runner_id`.
- `first_seen_at` é preservado e `last_seen_at` é atualizado a cada descoberta.
- A correlação existente por MAC, hostname e IP continua evitando duplicidade.
- API de targets devolve os novos campos sem remover os anteriores.
- Tela de Máquinas exibe status, hostname, fabricante, Runner, origem e datas.

## Migração
A migration `20260727_0016_asset_intelligence_enrichment.py` é aplicada pelo fluxo Alembic existente.

## Observação
Nesta sprint, todo host confirmado no scan é exibido como `online`. A transição automática para offline permanece planejada para a Sprint 2.4.
