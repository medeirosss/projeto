# MAGI 6.0.0 — Design System & Navigation (primeira entrega)

Baseline: MAGI 5.9.3 Hotfix 2. Entrega incremental de frontend.

## Implementado
- Tema visual compartilhado `frontend/magi-design-system.css` carregado nas telas operacionais.
- Paleta escura alinhada à referência aprovada: fundo #080F14, painéis #111D25, campos #192833, acento #C6FF57.
- Mantida personalização de cor via configuração existente; o verde-lima é o padrão na ausência de personalização.
- Navegação superior reorganizada: Overview, Assets, Security Validation, Attack Simulation, Monitoring & Alerts, Relatórios e Administração.
- Ocultados os links Status, Webhook e IP Scope da barra de Configurações, sem excluir backend, dados, formulários ocultos nem validações de escopo.
- Aplicados estilos comuns a tabelas, cards, botões, campos e navegação.

## Não incluído ainda
- Refatoração estrutural dos submenus e dos formulários de todos os módulos.
- Paginação universal com backend e tamanhos 25/50/100/500.
- Campaign Workspace, Attack Path interativo, dashboard novo, correlação visual e logs por módulo.
- Migrações de banco de dados (não necessárias para esta etapa).

## Homologação recomendada
1. Validar todas as páginas e a navegação no navegador com recarga forçada.
2. Testar branding salvo e comportamento dark/light.
3. Verificar que as opções Status, Webhook e IP Scope não aparecem no menu de Configurações.
4. Validar que configurações existentes continuam salvas e que o Campaign, Runner, Monitoring e Alertas seguem operando.
5. Comparar cada tela com as imagens de referência aprovadas. Registrar ajustes antes da 6.0.1.

## Limitações de validação
Sintaxe de common.js e settings.js verificada com node --check. Não foram executados testes integrados com PostgreSQL, Docker ou Runner Windows. Esta entrega não deve ser promovida a produção sem homologação.
