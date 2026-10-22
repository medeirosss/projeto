# Test Plan — Sprint 3.0.1

1. Atualizar backend e Runner para 2.12.1.
2. Confirmar `--doctor` e Nmap disponível.
3. Criar scan com Service Discovery habilitado.
4. Testar um Windows com firewall desabilitado ou portas conhecidas abertas.
5. Esperado: portas abertas aparecem em Ativos > Serviços.
6. Uma porta `unknown` deve continuar catalogada.
7. Repetir o scan: serviços não devem duplicar; `last_seen_at` deve atualizar.
8. Validar artefatos no job do Runner: `service_discovery_command.txt`, `service_discovery_stdout.txt`, `services.xml`, `services.json`.
