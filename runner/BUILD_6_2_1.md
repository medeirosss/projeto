# MAGI 6.2.1 — Campaign Details & Management

Base: 6.2.0 fornecida pelo usuário.

- Campaigns configuradas permanecem acima do formulário recolhido.
- Listagem com paginação 25/50/100/500.
- Ações principais Detalhes, Monitoring, Pausar/Retomar e menu de ações adicionais.
- Detalhes com indicadores de hosts, acessos, ciclos e arco de cobertura DHCP.
- Abas Overview, Attack Path, Rede, Cobertura, Evidências, Ciclos e Histórico.
- Denominador DHCP usa IPs únicos do snapshot; IP alcançado não equivale a autenticação.
- Histórico exibe registros de execução disponíveis, sem comparação temporal avançada.
- Backend, banco de dados e Runner preservados.

Validação: verificar sintaxe JS, integridade ZIP e teste integrado em Docker antes de produção.
