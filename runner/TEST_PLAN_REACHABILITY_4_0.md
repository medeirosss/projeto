# Test Plan — Reachability Preflight

## Caso A — host online + TCP/445 aberta
Esperado:
- status = success
- finding_status = detected
- reachability.status = reachable

## Caso B — host online + TCP/445 bloqueada
Esperado:
- status = success
- finding_status = not_detected
- reachability.status = reachable
- evidence.state = closed ou closed_or_filtered

## Caso C — host inexistente/desligado
Esperado:
- status = target_unreachable
- finding_status = not_evaluated
- confirmation_status = target_unreachable
- evidence.state = not_evaluated

## Caso D — serviço fechado com connection refused
Esperado:
- host considerado reachable
- finding_status = not_detected

## Caso E — hostname inválido/DNS inexistente
Esperado:
- status = target_unreachable
- finding_status = not_evaluated
- reachability.reason informa falha de resolução
