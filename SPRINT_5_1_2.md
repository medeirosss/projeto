# MAGI Sprint 5.1.2

## Objetivo
Hotfix de transporte/autenticação WinRM para Runner fora do domínio e padronização visual exclusiva da tela Attack Simulator.

## Authentication Transport
- TrustedHosts temporário restrito ao host necessário; nunca usa `*` automaticamente.
- Usa o provider WSMan quando disponível e fallback pelo registro em `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client`, valor `trusted_hosts`, quando o provider não existe.
- Restaura o estado original no `finally`; se o valor não existia antes, remove o valor criado.
- No salto A → B, aplica a mesma lógica temporária no Host A apenas para o Host B, restaurando depois.
- Não altera firewall, GPO ou membership de domínio.

## Diagnóstico por estágio
Falhas distinguem `runner_preflight`, `runner_to_host_a` e `host_a_to_host_b`.

## Interface
Somente a tela Attack Simulator foi alinhada ao topbar padrão global. As demais telas não foram alteradas.
