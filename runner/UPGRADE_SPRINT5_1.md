# Upgrade 5.0 → 5.1

1. Substitua backend/frontend/runner pelos arquivos desta build.
2. Reinicie backend e Runner.
3. Abra Attack Simulator e clique em **Sincronizar catálogo**.
4. Para o teste lateral, use uma Credential Profile Windows/WinRM existente em Ações.
5. Garanta que WinRM esteja autorizado entre Runner→A e A→B. O MAGI não altera TrustedHosts/GPO/firewall automaticamente.
