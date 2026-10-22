# Test Plan — Sprint 3.1

1. Atualize backend e Runner para 2.13.0.
2. Confirme no doctor que `credential_validate` está autorizado.
3. Cadastre uma credencial Windows em Configurações > Credenciais.
4. Crie um novo scan e selecione essa credencial.
5. Execute contra um host Windows acessível por WMI/DCOM ou WinRM.
6. No pipeline, Credential Engine deve sair de pending/running para success ou failed.
7. Confirme `Tentativas <= 2`.
8. Se o ativo estava sem hostname, confirme que hostname foi preenchido após autenticação bem-sucedida.
9. Confirme que uma senha incorreta não impede o ativo de permanecer no inventário.
10. No PostgreSQL, confirme que `stored_credentials.secret_encrypted` começa com `ENC:` e que `runner_jobs.payload` contém somente `credential_id`, nunca a senha.
