# MAGI Sprint 5.3.1 — Campaign Discovery / Precondition Fix

## Objetivo
Corrigir a explosão de jobs observada na 5.3 e impedir que endereços não detectados sejam promovidos a Assets.

## Correções
- Novo executor Runner `campaign_probe`: um único preflight por candidato antes de qualquer autenticação.
- Preflight verifica ICMP, portas relevantes (22/445/5985/5986) e, quando configurado, SNMP v2c/sysName.
- WinRM, SMB e SSH só são enfileirados quando o serviço correspondente passou a precondition.
- SNMP confirmado no preflight é persistido como relação `discovery`, sem duplicar o teste de community.
- Candidato sem resposta ao preflight não é criado em `attack_campaign_assets`.
- Credenciais deixam de funcionar como mecanismo genérico de host discovery.
- Falhas de execução, transporte e autenticação passam a ser classificadas separadamente.
- `paramiko` ausente passa a ser `runner_dependency_missing`, e não `access_not_confirmed`.
- WinRM/TrustedHosts e falhas equivalentes são `transport_failed`.
- Erros SMB de domínio/rede são `transport_failed`; rejeições reais de credencial são `authentication_failed`.
- Timeout da Campaign permanece inalterado: a correção reduz trabalho inútil em vez de ampliar a janela.
- Configurações existentes do Runner migram automaticamente para habilitar `campaign_probe`.

## Fluxo 5.3.1
Candidate -> campaign_probe -> host detectado -> protocolos aplicáveis -> credential_validate -> access_confirmed -> nova frontier.

Host não detectado -> DROP (sem Asset e sem fan-out de credenciais).

## Compatibilidade
O schema existente é preservado. Não há migração destrutiva de banco. Campaigns 5.3 já cadastradas podem continuar usando os mesmos Credential Profiles.
