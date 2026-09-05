# Test Plan — Sprint 3.3

1. Aplicar migrations e confirmar `20260810_0024 (head)`.
2. Abrir `/exposicoes` e clicar em **Reavaliar** para popular findings a partir do estado atual.
3. Em um host Windows com SMB/RDP, confirmar findings correspondentes conforme portas abertas.
4. Criar uma regra de processo, executar Deep Inventory e confirmar finding de processo.
5. Repetir scan: findings não devem duplicar; apenas `last_seen_at` deve atualizar.
6. Fechar/remover a condição e repetir a engine: finding deve virar `resolved`, preservando histórico.
7. Marcar finding como `ignored` e confirmar que permanece ignorado enquanto a evidência existir.
8. Em Ativos, confirmar contagem de exposições e painel por ativo.
9. Alterar RAM numa VM e confirmar histórico mostrando valores em GB no frontend.
