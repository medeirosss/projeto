# MAGI Sprint 5.3 — Multi-Protocol Campaign

## Objetivo
Evoluir o Attack Campaign Engine 5.2 para avaliar múltiplos protocolos sem transformar a Campaign em um executor de payloads ofensivos.

## Entregas
- Windows: validação autenticada WinRM e SMB/IPC$ com a credencial Windows selecionada.
- Linux/Unix: validação SSH com execução benigna de `hostname` para prova de acesso.
- Network Node: SNMP v2c com community armazenada no Credential Store; consulta de `sysName.0` como prova de discovery.
- Credenciais independentes por Campaign: Windows, SSH e SNMP v2c.
- Vetores habilitáveis individualmente: WinRM, SMB, SSH e SNMP v2c.
- Paths passam a registrar `protocol` e `relation_type` (`access` ou `discovery`).
- Apenas relações de acesso autenticado podem promover um host para a frontier de acesso. SNMP é discovery e não é tratado como comprometimento/pivot.
- Segredos continuam fora de `runner_jobs`; são injetados transitoriamente quando o Runner coleta o job.

## Semântica
`access_confirmed`: autenticação e operação remota benigna confirmadas pelo protocolo.

`discovery_confirmed`: SNMP respondeu com a community autorizada e retornou identidade básica. Não significa shell, comprometimento ou capacidade de pivot.

## Fora do escopo
- RDP foi removido da evolução da Campaign 5.3. O catálogo legado pode permanecer, mas Campaign não usa RDP.
- SSH real originado de um host Linux comprometido para outro host fica para evolução posterior. Na 5.3 a prova SSH é executada pelo Runner.
- Coleta de MAC table/ARP/LLDP/CDP e comandos read-only em switches/roteadores ficam para build futura.
- Attack Graph, reorganização do histórico e revisão ampla do frontend ficam para Build 6.
- Payload ofensivo não é executado pela Campaign.
