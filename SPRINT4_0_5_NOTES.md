# MAGI Sprint 4.0.5

## Objetivo principal
Transformar o target Atomic em alvo real de execução. A partir desta build, jobs Atomic não executam localmente no Runner como fallback.

## Remote Execution
- Atomic remoto via PowerShell Remoting / WinRM.
- Target e credencial Windows/WinRM são obrigatórios.
- A credencial é armazenada apenas por ID em `runner_jobs`; o segredo é injetado transitoriamente quando o Runner busca o job.
- O Runner faz preflight da porta WinRM antes de iniciar a sessão.
- O runtime Atomic é preparado no endpoint em `C:\ProgramData\Magi\AtomicRuntime`.
- O módulo Invoke-AtomicRedTeam e a pasta da técnica são copiados do Runner para o target.
- `Invoke-AtomicTest -GetPrereqs` é executado no target antes da execução real.
- Não existe fallback para execução local.

## Novos estados de evidência
- `target_unreachable`: target sem conectividade WinRM.
- `authentication_failed`: falha de autenticação.
- `remote_transport_error`: sessão WinRM não pôde ser aberta.
- `dependency_missing`: pré-requisito/dependência Atomic ausente ou não obtido.
- `runner_dependency_error`: Runner sem módulo/pasta Atomic necessários.
- `prevented`: controle de segurança interferiu.
- `not_confirmed`: execução iniciou, mas retornou erro/exit code Atomic não-zero.
- `executed_unverified`: Atomic executado sem confirmação independente do efeito.

## Correções
- `192,168,0,100` e outros targets malformados são rejeitados no backend e no frontend.
- `Exit code: 1` interno do Atomic prevalece sobre o exit code 0 do wrapper PowerShell.
- Dependência ausente deixa de ser apresentada como sucesso.
- Saída PowerShell remota é solicitada em UTF-8.
- Runner version: 2.15.0.

## Observação operacional
A execução remota Windows depende de WinRM disponível no endpoint e de uma credencial administrativa compatível. Em WinRM HTTP, quando necessário, o Runner pode adicionar temporariamente o target ao TrustedHosts e restaurar a configuração ao final.
