# Upgrade Sprint 5.2

1. Substitua backend/frontend/runner pela Build 5.2 preservando `.env`, banco e configuração do Runner.
2. Execute Alembic conforme o procedimento já utilizado pelo MAGI. O startup também possui safety-net idempotente para as tabelas de Campaign.
3. Reinicie backend e Runner.
4. Abra `/attack-simulator`, sincronize o catálogo e valide o END-101 manual.
5. Crie a primeira Attack Campaign com scope CIDR, 1–3 seeds, Credential Profile, período e janela diária.
6. Para laboratório, recomenda-se começar com `/24`, 1 seed e uma janela curta antes de campanhas de vários dias.

A Build 5.2 não exige Nuclei e não adiciona Metasploit. Campaigns usam somente o fluxo benigno WinRM validado na 5.1.2.
