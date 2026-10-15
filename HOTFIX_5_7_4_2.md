# MAGI 5.7.4.2
- Ver IPs lê apenas snapshot persistente.
- Atualizar DHCP dispara consulta explícita, commit somente em sucesso.
- Lista DHCP remove expiração e inclui credenciais Windows por endpoint.
- Scan Now DHCP exige credencial e usa pipeline Discovery/Service Discovery/Deep Inventory.
- Scan Now de Ativos passa a criar scan host-only com credencial selecionada, sem reutilizar configuração Nmap-only da origem.
- Preservados Campaign, WinRM e TrustedHosts.
## Homologação
1. Ver IPs não cria jobs.
2. Atualizar DHCP cria um windows_dhcp_inventory e persiste apenas em sucesso.
3. Falha de atualização mantém snapshot anterior.
4. Scan Now em DHCP/Ativos cria nmap_discovery e, após resposta e serviços, executa Credential Engine e Deep Inventory.
5. Conferir logs do Runner, credenciais, resultado do ativo e cobertura Campaign.
## Limitações
O pipeline de Deep Inventory depende de disponibilidade do host, autenticação e serviços remotos. Testes integrados em Windows/Runner/PostgreSQL pendentes.
