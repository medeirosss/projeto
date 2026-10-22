# Test Plan — Sprint 5.1

1. Sincronize o catálogo e confirme nomes `Protocol Reachability`.
2. Execute RDP Protocol Reachability: `status=success` deve representar o job; `attack_result=precondition_confirmed` quando houver negociação.
3. Cadastre uma Credential Profile Windows/WinRM.
4. Selecione `MAGI-ATK-END-101`, informe Host A e Host B.
5. Planeje e confirme `scope.max_hops <= 5`, `allowed_hosts=[A,B]` e discovery desativado.
6. Execute: em sucesso, evidência deve mostrar A e B, `hop_count=1`, artefatos verificados e cleanup em ambos.
7. Desligue Host B ou bloqueie WinRM e repita: job deve terminar, mas `attack_result=lateral_movement_not_confirmed`.
8. Confirme que senha não aparece no histórico, stdout ou evidence.
