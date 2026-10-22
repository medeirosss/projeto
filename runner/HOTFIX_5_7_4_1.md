# MAGI 5.7.4.1 — DHCP Coverage, Deep Inventory e cache

- DHCP: snapshot de leases por integração persistido em `app_settings` (module `dhcp_cache`) apenas após resultado bem-sucedido e metadados completos. A interface recupera o último snapshot antes de solicitar atualização e mantém os dados quando o Runner falha.
- Scan Now: ativa o estágio Service Discovery. Permite informar o ID de uma credencial **do endpoint**, distinta da credencial do servidor DHCP; quando fornecida, ativa o pipeline de Credential Engine + Deep Inventory após autenticação bem-sucedida. Sem credencial do endpoint, não promete Deep Inventory.
- Campaign: exibe indicador DHCP na abertura do detalhe e abre a aba Coverage, com porcentagem de IPs de leases alcançados. O cálculo existente da execução permanece inalterado.
- Preservados: WinRM, TrustedHosts, Campaign stateful, Attack Path, módulos do Runner.

## Testes em homologação
1. Abra Ver IPs: confirme lista e timestamp do último sucesso. Desligue temporariamente a consulta DHCP e confirme que a lista permanece com indicação de cache.
2. Execute Scan Now com credencial Windows válida para a máquina alvo. Verifique jobs nmap_discovery, service_discovery, credential e deep_inventory; este último depende de autenticação confirmada.
3. Abra um Campaign com DHCP habilitado, selecione Coverage e valide a proporção contra o snapshot daquela execução.

Limitações: testes de sintaxe e estáticos não substituem validação WinRM, banco PostgreSQL e Runner Windows. Cache antigo começa a ser populado na primeira atualização bem-sucedida desta versão.
