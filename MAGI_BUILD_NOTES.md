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

## Build 5.4.1 — Evidence Integrity Hotfix
- `Ver` renomeado para `Attack Path`.
- ICMP só confirma discovery quando TTL e o IPv4 exato do target aparecem na mesma resposta.
- Resposta de gateway/roteador/outro IP não promove o candidato a host.
- `preflight` é apresentado como `Discovery / ICMP`.
- Discovery não confirmado permanece em Evidências, mas não entra no Attack Path.
- Barriers passam a carregar `reason` legível, preservando o resultado técnico bruto.

## Build 5.4.2 — WinRM Campaign Consistency
- WinRM do `credential_validate` da Campaign passa a usar o mesmo contrato de transporte do `MAGI-ATK-END-101`.
- TrustedHosts é lido, ajustado temporariamente para o target e restaurado em `finally`.
- `Invoke-Command` usa explicitamente `-Authentication Negotiate`.
- Falhas WinRM ganham classificação adicional: `trustedhosts_failed`, `timeout`, `service_unavailable`, além de `authentication_failed` e `transport_failed`.
- Attack Path/Evidências traduzem essas classes em motivos legíveis.
- Nenhum novo ataque, payload ou mudança de política/branch da Campaign foi introduzido.

## Build 5.4.3 — Campaign Result Ingestion & Evidence
- Resultado terminal de `credential_validate` da Campaign é ingerido imediatamente no recebimento do Runner.
- A promoção para `access_confirmed` não depende mais de o ciclo continuar com status `running`.
- `_sync_paths()` permanece como reconciliação/fallback.
- `create_benign_evidence` passa a ser enviado no payload dos jobs de acesso.
- Em WinRM confirmado, o Runner cria e verifica `C:\MAGI\MAGI_EVIDENCE.txt` usando WinRM/Negotiate e TrustedHosts temporário.
- Em SMB confirmado, o Runner tenta criar e verificar o mesmo artefato via `C$`.
- Falha ao criar a evidência não apaga um acesso já confirmado; é registrada separadamente em `evidence_error`.
- Attack Campaign Asset recebe `access_method`, `evidence_requested`, `evidence_created`, `evidence_verified` e `evidence_path`.

## Build 5.4.4 — Protocol Visibility & Same-Flow Evidence
- Runner Jobs passa a exibir a coluna `Protocol`, resolvida por `attack_campaign_paths.protocol` ou pelo payload do job.
- WinRM cria e verifica a evidência na mesma sessão remota que confirma o acesso; não abre uma segunda autenticação.
- SMB mantém `IPC$` como prova de acesso e, no mesmo fluxo PowerShell, tenta `C$` apenas para a evidência.
- Falha de escrita em `C$` não invalida o acesso SMB confirmado; fica registrada em `evidence_error`.
- Conteúdo do artefato foi simplificado para `MAGI esteve aqui` e `Data/Hora: dd/MM/yyyy HH:mm:ss`.
- Caminho Windows: `C:\MAGI\MAGI_EVIDENCE.txt`.
- Texto da UI atualizado para `Criar evidência benigna no host`.
- O ajuste geral de timezone da interface não faz parte desta build.
