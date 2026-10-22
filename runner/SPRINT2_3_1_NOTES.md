# Sprint 2.3.1 — Enrichment & Asset Compliance

## Escopo entregue
- Pipeline visual do scan: Discovery, DNS, Fingerprint, Classificação e Inventário.
- Resultado por ativo com estados success/failed/inconclusive/skipped/pending.
- Novos ativos: somente ativos criados no último scan concluído, sem criar um inventário paralelo.
- Ativos analisados: inventário consolidado e completo, incluindo os novos.
- Compliance com 3 regras independentes: Servidores, Desktops e Nós de rede.
- Condições simples e cumulativas de Início, Contém e Final.
- Confidence Engine explicável com pesos fixos do Magi e regras do ambiente definidas pelo técnico.
- Aba Pontuação com todos os critérios e faixas de confiança.
- Evidências de confiança persistidas e consultáveis por ativo.
- Política opcional de cleanup por scans consecutivos ausentes, mínimo 3.
- Cleanup usa soft-retire; target_uuid e histórico/auditoria são preservados.
- Reaparecimento reativa automaticamente o ativo e zera consecutive_misses.

## Fora do escopo
- Estado operacional Online/Offline.
- Service Discovery.
- CVEs.
- Agente local.
- Endpoint Central como dependência do Discovery.

## Migration
Head: `20260806_0019`.
