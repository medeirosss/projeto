# Test Plan — MAGI 5.3

1. Atualização: subir backend preservando PostgreSQL e confirmar Alembic head `20260829_0027`.
2. Credential Store: cadastrar/confirmar um perfil Windows, um SSH e uma community SNMP v2c conforme o laboratório disponível.
3. Criar Campaign 5.3 com scope autorizado e ao menos um seed. Selecionar somente os vetores que possuem credencial configurada.
4. Windows/WinRM: em host autorizado com WinRM funcional, confirmar path `protocol=winrm`, `relation_type=access` e `access_confirmed`.
5. Windows/SMB: em host autorizado com TCP/445 e credencial válida, confirmar autenticação em IPC$ sem criação de arquivo remoto.
6. SSH: em Linux autorizado, confirmar autenticação e retorno de `hostname`; validar que o host passa a `access_confirmed`.
7. SNMP v2c: em equipamento autorizado, confirmar `sysName.0`; validar `relation_type=discovery` e que o equipamento NÃO vira pivot de acesso.
8. Negativos: testar credencial/community incorreta e porta/protocolo indisponível; resultado deve ser `*_not_confirmed`, sem marcar acesso.
9. Scope: confirmar que nenhum target fora dos CIDRs da Campaign é agendado.
10. Regressão 5.2: pausa/retomada, ciclos de 15 min, política 10→5→1→0 e snapshots continuam operacionais.
