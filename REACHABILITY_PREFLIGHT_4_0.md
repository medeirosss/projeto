# MAGI 4.0 — Target Reachability Preflight

A camada de Reachability foi adicionada antes dos MAGI Security Checks TCP.

## Objetivo
Evitar que um host inexistente/desligado seja classificado como `not_detected` apenas porque uma porta TCP não respondeu.

## Evidências usadas
1. Porta do próprio check: `open` ou `connection refused` comprovam host alcançável.
2. ICMP, quando permitido.
3. ARP/L2, de alto valor em redes locais.
4. Probes TCP alternativos em portas conhecidas.

## Estados
- `reachable`: existe evidência de vida do target; o check de segurança pode ser interpretado.
- `target_unreachable`: nenhuma evidência de reachability; a condição de segurança fica `not_evaluated`.
- `detected`: target alcançável e condição encontrada.
- `not_detected`: target alcançável e condição não encontrada.

A ausência de resposta em todos os métodos significa "sem evidência de reachability", não prova matemática de que o host não existe. Isso evita falso `not_detected`.
