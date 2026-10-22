# MAGI Build 6.0.1 — Frontend Design System

## Implementado
- Contrato CSS central em frontend/design-system/{tokens,layout,components}.css, importado ao final dos estilos em todas as 9 páginas autenticadas.
- Shell compartilhado para topbar, navegação, cartões, tabelas e Attack Simulator; mantém os IDs, scripts e funcionalidades existentes.
- Painel global de branding no cabeçalho, com nome, logo, sete cores e modo claro/escuro.
- Branding salvo via POST /api/settings com payload parcial `theme` (backend deep_merge); a API é fonte autoritativa. Modo claro/escuro permanece preferência do navegador.
- Página Administração continua podendo alterar branding e é sincronizada ao salvar.
- Identificação `UI 6.0.1` no cabeçalho para comprovar deploy. Assets com query versionada.

## Limites e validação
- Refatoração incremental sem mudanças em Runner, Campaign, banco, API de simulação ou migrações.
- Executar teste visual e funcional em Docker: cabeçalho/branding em Overview, Assets, Security Validation, Attack Simulation, Monitoring, Relatórios e Administração; salvar tema e recarregar; testar menus e execução em ambiente autorizado.
- A aplicação não foi executada com serviços reais neste ambiente de empacotamento.
- Estilos legados ainda existem para componentes específicos, mas tokens/layout/componentes compartilhados têm precedência por ordem de importação. Migração total de estilos locais deve ser feita progressivamente.
