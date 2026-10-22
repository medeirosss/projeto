# MAGI 4.0 — ICMP Reachability Fix

Correção do Target Reachability Preflight.

## Problema
No Windows, `ping.exe` pode retornar código 0 mesmo quando um gateway responde com
`Host de destino inacessível`. Isso gerava falso positivo de reachability.

## Correção
ICMP só passa a contar como evidência positiva quando:
- existe uma linha de resposta do próprio IP consultado;
- existe TTL na resposta;
- não há mensagens de `destination host unreachable`, timeout ou falha geral.

O retorno do processo sozinho deixa de ser suficiente.
