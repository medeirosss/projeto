# Test Plan — Sprint 5.1.1
1. Runner fora do domínio, Host A no domínio, WinRM/5985 habilitado.
2. Executar END-101 com Credential Profile autorizada e FQDN para A/B.
3. Confirmar criação/verificação/cleanup em A.
4. Confirmar que B é invocado a partir da sessão em A.
5. Confirmar restauração exata do TrustedHosts do Runner após sucesso e após falha.
6. Confirmar ausência de segredo em stdout/evidence/history.
7. Confirmar que movimento lateral só fica `confirmed` quando A e B produzem evidência e cleanup.
