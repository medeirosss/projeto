# Magi Roadmap até Golden Image 1.0

## Escopo fechado
Este roadmap é a referência oficial do projeto até a Golden Image 1.0. Novas ideias ficam para a versão 1.1, exceto correções de bug, segurança ou regressão.

## Fases
1. Validation Engine 1.0
   - Sprint 1: Validation History — status: entregue em 0.8.0
   - Sprint 2: Evidence Engine — pendente
   - Sprint 3: Dashboard — pendente
   - Sprint 4: Runner Enterprise — pendente
2. Alert Intake — pendente
3. Correlation Engine — pendente
4. Incident Engine — pendente
5. Recommendation Engine — pendente
6. Playbook Engine — pendente
7. Action Engine — pendente
8. Approval Workflow — pendente
9. SOAR-lite — pendente
10. UX/UI Golden Image — pendente

## Definition of Done por sprint
- Backend, frontend, banco e runner compatíveis.
- Docker sobe sem alteração manual não documentada.
- Changelog, upgrade e plano de testes atualizados.
- Ambiente de homologação validado antes da próxima sprint.

## Atualização após Build 4.2
- Build 4.x: Vulnerability Validation / Nuclei — base estabilizada.
- Build 5.0: MAGI Attack Simulator Foundation — catálogo nativo remoto, não destrutivo, dividido em Endpoint, Active Directory, Network Node e Application.
- Próximas 5.x: evolução incremental de simulações autenticadas benignas, evidência de detecção/prevenção e encadeamento controlado de caminhos de ataque.

## Build 5.2 — Attack Campaign Engine
- Campaigns multi-day com janela diária e ciclos de 15 minutos.
- 1–3 seeds iniciais, promoção automática de pivots e política 10/5/1/0.
- Scope CIDR obrigatório, inventário básico e snapshots históricos (10 por Campaign).
- Attack Graph visual permanece para Build 6.

## Build 6 — Attack Graph
- Primeira visualização gráfica de hosts, paths, estados e frontier.
- Comparação entre snapshots/Executions para medir paths mitigados, novos paths e novos ativos.
