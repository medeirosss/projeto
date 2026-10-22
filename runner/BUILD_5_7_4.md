# MAGI 5.7.4 — DHCP Coverage & Scan Now

- Preserva o snapshot DHCP e a métrica Campaign DHCP coverage existentes.
- Lista leases ativos por consulta sob demanda ao Runner, incluindo IP, hostname, client ID, escopo e expiração.
- Scan Now manual individual reutiliza o Discovery existente e exige confirmação explícita de autorização.
- Backend confere que o IP consta no resultado real do job DHCP para o servidor configurado.
- Sem descoberta automática, ataques, ou alterações em WinRM/TrustedHosts.

## Validação em Windows
1. Abra Configurações > Integrações > DHCP, clique Ver IPs.
2. Confira leases ativos e inicie Scan Now de um IP autorizado.
3. Acompanhe Discovery e confirme que apenas o IP selecionado foi varrido.
4. Execute Campaign e confira DHCP coverage e snapshot.
