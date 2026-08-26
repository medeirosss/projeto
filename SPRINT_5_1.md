# MAGI Sprint 5.1 — Controlled Lateral Movement

## Objetivo
Separar definitivamente sucesso de execução do Runner do resultado do ataque e introduzir o primeiro salto lateral benigno comprovável.

## Entregas
- Semântica separada: `execution_status`, `attack_result`, `payload_status`, `authentication_status`, `lateral_movement_status`, `detection_status`.
- Renomeação dos testes de superfície para **Protocol Reachability / Telemetry**.
- Novo `MAGI-ATK-END-101 — WinRM Lateral Movement Path Validation`.
- Caminho manual **Host A → Host B** com Credential Profile já armazenado no MAGI.
- Artefato benigno temporário `C:\MAGI\magi-was-here-<token>.txt`, verificação e cleanup automático em A e B.
- O comando para Host B é originado dentro da sessão remota de Host A, comprovando o salto.
- Attack Scope 5.1 com `max_hops` configurável 1–5 e hard limit 5; `max_branches_per_host`, `max_total_hosts` e timeout já modelados.
- Na 5.1, descoberta automática está **desativada**; A e B são informados manualmente.

## Limites nativos
- hard max hops: 5
- default max hops: 3
- default branches/host: 3
- default total hosts: 15
- default job duration: 30 min
- visited-host/branch expansion entram na fase de descoberta automática; 5.1 executa apenas 1 hop manual.

## Segurança
- O segredo da Credential Profile é injetado apenas na resposta transitória para o Runner; não é persistido no payload do runner job.
- Senha não integra stdout/evidence.
- Nenhuma alteração de TrustedHosts é feita automaticamente.
- Nenhum exploit/CVE/brute force é executado.
