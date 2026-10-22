# Test Plan — Sprint 5.1.2

1. Runner fora do domínio; Host A/B Windows autorizados e WinRM disponível.
2. END-101 por IP: confirmar fallback `registry` quando `WSMan:` não existir no Runner.
3. Confirmar artefato e cleanup no Host A.
4. Confirmar salto originado no Host A e artefato/cleanup no Host B.
5. Confirmar restauração do TrustedHosts do Runner e do Host A após sucesso e falha.
6. Validar `failure_stage` para preflight, primeiro hop e segundo hop.
7. Abrir `/attack-simulator` e validar topbar no padrão das demais telas.
