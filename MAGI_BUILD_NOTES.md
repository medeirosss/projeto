# MAGI — Build Notes

## Baseline
A Build 5.4.0 deriva diretamente da 5.3.12, validada como baseline estável da Campaign.

## Build 5.4.0 — Attack Path & Evidence
Objetivo: transformar os resultados técnicos de cada Campaign em um Attack Path rastreável, sem misturar Campaigns distintas.

### Entregas
- Attack Path individual por Campaign e pela execução mais recente.
- Endpoint `GET /api/attack-simulator/campaigns/{campaign_uuid}/attack-path`.
- Consolidação de nodes, edges, barriers e evidence a partir dos dados persistidos pela Campaign.
- Resumo: IPs avaliados, hosts conhecidos, acessos confirmados, maior hop, SNMP, barreiras, cycles e acessos por protocolo.
- Classificação visual: ACCESS CONFIRMED, SNMP/DISCOVERY ONLY, AUTHENTICATION FAILED, TRANSPORT FAILED, SERVICE UNAVAILABLE e BARRIER.
- Evidência mantém referências de path, cycle, hop e Runner Job.
- Interface da Campaign com abas Resumo, Attack Path, Evidências e Ciclos.
- SNMP continua discovery-only e não é apresentado como pivot confirmado.
- Nenhum novo exploit, payload ou alteração do motor de Campaign da 5.3.12.

### Regra arquitetural
Attack Paths nunca são consolidados globalmente entre Campaigns. Cada grafo pertence a uma Campaign e mantém a rastreabilidade da execução que o originou.

## Próximo marco
Após validação da 5.4, a Build 5.5 permanece reservada para Pentest manual/controlado.
