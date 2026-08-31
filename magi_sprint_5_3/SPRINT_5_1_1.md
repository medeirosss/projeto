# MAGI Sprint 5.1.1 — WinRM Authentication Transport

## Objetivo
Permitir que o MAGI Runner fora do domínio valide o primeiro acesso WinRM ao Host A sem exigir ingresso do Runner no domínio e sem deixar alteração permanente em TrustedHosts.

## Estratégia
- O Runner mantém-se fora do domínio.
- Para WinRM HTTP autenticado, o executor usa `Negotiate` com a Credential Profile autorizada.
- Antes do primeiro acesso, o Runner lê o TrustedHosts atual e adiciona **somente o Host A** durante a execução.
- Wildcard (`*`) não é utilizado.
- Em bloco `finally`, o valor original de TrustedHosts é restaurado, inclusive quando o teste falha.
- O Host B continua sendo acessado a partir do Host A com credencial explícita; preferir FQDN para destinos de domínio.
- O segredo continua transitório e não é gravado em evidência/histórico.

## Segurança
A mudança de TrustedHosts ocorre apenas no Runner, não no DC/endpoint alvo. O Runner precisa executar com privilégio suficiente para alterar WSMan local. O MAGI não altera firewall, GPO, WinRM do alvo ou TrustedHosts dos alvos.

## Limitação conhecida
A Sprint 5.1.1 resolve o bloqueio Runner fora do domínio -> Host A. O salto A -> B ainda pode falhar por política WinRM/Kerberos/NTLM no ambiente e deve ser reportado como estágio separado, nunca como ataque confirmado.
