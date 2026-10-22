# MAGI 5.9.3 — Event & Alert Management

- Mantém o Monitoring Light de 60 minutos, sem autenticação, com primeira execução imediata e botão Verificar agora.
- Persiste alertas internos derivados de eventos confirmados, com chave única por evento para evitar duplicações.
- Severidade inicial: warning para indisponibilidade/mudança de serviço, info para recuperação. Não representa avaliação de vulnerabilidade.
- Reconhecer ou encerrar alerta aberto por API e fluxo simples no botão Monitoring; eventos originais não são alterados.
- Endpoints: GET /api/security-monitoring/campaigns/{uuid} (inclui alerts); POST /api/security-monitoring/campaigns/{uuid}/alerts/{id}/acknowledge e /close.
- Bootstrap cria security_monitor_alerts sem apagar dados anteriores.
- Atenção: eventos antigos são materializados no próximo tick do scheduler; os alertas não enviam notificações externas.
- Homologação: mudar serviço conhecido, confirmar duas observações, verificar evento/alerta único, reconhecer/encerrar, reiniciar backend, confirmar persistência, restaurar serviço e verificar novo evento.
- Limitação herdada da 5.9.2: a interpretação do payload depende do formato de resultados reais do Runner; testar com PostgreSQL e Runner Windows.
