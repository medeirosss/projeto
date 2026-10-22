# Test Plan — Sprint 4.0.5

## Teste 1 — Target inválido
1. Em Tarefas, informe `192,168,0,100`.
2. Selecione uma credencial.
3. Execute um Atomic.
4. Esperado: requisição rejeitada como target inválido; nenhum job remoto deve ser executado.

## Teste 2 — Target desligado
1. Desligue o endpoint de homologação.
2. Informe o IP correto.
3. Selecione uma credencial Windows/WinRM.
4. Execute um Atomic.
5. Esperado: `status=failed`, `finding_status=target_unreachable`, `execution_scope=target_remote`, `executed_real_test=false`.

## Teste 3 — Target ligado / credencial incorreta
1. Ligue o endpoint e confirme WinRM disponível.
2. Use uma credencial inválida.
3. Execute.
4. Esperado: `authentication_failed` ou `remote_transport_error`; nenhuma execução local no Runner.

## Teste 4 — Execução remota real
1. Use endpoint ligado e credencial administrativa válida.
2. Execute uma técnica simples compatível com Windows.
3. Esperado no histórico:
   - `execution_scope=target_remote`
   - `requested_target=<IP>`
   - `execution_host=<hostname do endpoint>`
   - `attempted_real_test=true`
   - nunca `runner_local`.

## Teste 5 — Dependência
1. Execute T1003 #1 (Gsecdump).
2. O Runner deve preparar o runtime e chamar `-GetPrereqs` no target.
3. Se o prerequisito não puder ser obtido, esperado: `status=failed` e `finding_status=dependency_missing`.
4. Se o prerequisito estiver disponível, o teste segue para execução.

## Teste 6 — Exit code interno
1. Execute um Atomic cujo comando interno retorne `Exit code: 1`.
2. Esperado: o histórico não pode mostrar execução bem-sucedida baseada apenas no wrapper PowerShell.
