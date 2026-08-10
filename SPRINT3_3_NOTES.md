# Sprint 3.3 — Exposure Engine

## Escopo
- Findings de exposição derivados de Service Discovery e Process Intelligence.
- Estados: open, resolved e ignored.
- Severidades: info, low, medium, high, critical.
- Evidence explicável em JSONB.
- Exposure Knowledge Base em `backend/config/exposure_knowledge.yaml`.
- Tela principal `/exposicoes` com filtros, resumo e ação Ignorar/Reabrir.
- Contagem de exposições abertas em Ativos e detalhe por ativo.
- Reavaliação automática após Service Discovery e Deep Inventory.
- Rebuild manual para ativos já existentes.
- Correção visual: memória e mudanças de memória exibidas em GB; bytes permanecem no banco.

## Fora do escopo
CVE/NVD/CVSS/EPSS, exploração, NSE de vulnerabilidades, remediação automática e SOAR.
