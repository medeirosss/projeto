# Test Plan — Sprint 3.2

1. Atualize backend/database e Runner para 2.14.0.
2. Em Ativos > Processos, crie uma regra para um processo de laboratório (ex.: `notepad.exe`, categoria Não autorizado).
3. Crie um Scan com credencial Windows válida e habilite Deep Inventory em 10, 30 ou 60 minutos.
4. Execute o scan e acompanhe o pipeline até Deep Inventory = success.
5. Em Ativos analisados > Deep Inventory, valide SO/build, domínio, fabricante, modelo, serial, CPU, RAM e discos.
6. A primeira coleta não deve criar histórico de mudança de hardware.
7. Execute novamente sem alterar hardware: não deve criar novo evento em `asset_hardware_changes`.
8. Execute o processo cadastrado e rode Deep Inventory: o processo deve aparecer em Process findings.
9. Feche o processo e rode novamente: o finding deve permanecer no histórico com `currently_detected=false`.
10. Confirme que uma falha no Deep Inventory não remove o ativo nem invalida Discovery/Service Discovery.
