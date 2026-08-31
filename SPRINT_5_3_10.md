# Sprint 5.3.10 - Campaign ICMP Admission Gate

## Regra
Um endereço candidato só participa da Campaign quando responde a um ICMP Echo Request com Echo Reply real (`TTL=`).

Fluxo:
1. Candidate IP
2. ICMP ping
3. Sem TTL -> drop (`discovery_not_confirmed`)
4. Com TTL -> host confirmado
5. Service discovery (WinRM/SMB/SSH/SNMP)
6. Credential validation apenas nos protocolos aplicáveis

A existência de porta TCP aberta ou resposta SNMP não substitui o requisito de ping nesta versão.
