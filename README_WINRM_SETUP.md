# Centric v2 - WinRM / PowerShell remoto

Esta versão adiciona suporte a execução de playbooks `.ps1` em um host Windows remoto via WinRM, mantendo a aplicação em container Linux.

## Quando usar

Use `remote_winrm` quando o script depender de recursos Windows, por exemplo:

- módulo ActiveDirectory/RSAT;
- comandos PowerShell para AD;
- ações locais em servidores Windows;
- comandos que não funcionam dentro do container Linux.

## Preparar o host Windows executor

PowerShell como Administrador:

```powershell
Enable-PSRemoting -Force
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
```

Para homologação com HTTP/5985 e transporte NTLM:

```powershell
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

Produção recomendada:

- WinRM HTTPS na porta 5986;
- certificado válido no listener;
- `AllowUnencrypted=false`;
- conta com permissões mínimas necessárias.

## Configurar no portal

Acesse:

```text
Ações > Repositório de credenciais
```

Crie uma credencial:

```text
Tipo: WinRM / PowerShell remoto
Usuário: DOMINIO\usuario ou usuario@dominio.local
Senha: senha da conta
Host WinRM: IP ou DNS do executor Windows
Porta: 5985 para HTTP ou 5986 para HTTPS
Transporte: ntlm, basic ou kerberos
Usar HTTPS: marcar quando usar 5986
```

Depois envie um playbook `.ps1` em:

```text
Ações > Repositório de scripts
```

Na execução manual ou por alerta, selecione a credencial WinRM. Quando a credencial for do tipo `winrm`, a execução será remota automaticamente.

## Variáveis disponíveis no script remoto

O portal injeta variáveis de ambiente no PowerShell remoto:

```powershell
$env:CENTRIC_HOSTNAME
$env:CENTRIC_IP
$env:CENTRIC_USERNAME
$env:CENTRIC_TARGET_USER
$env:CENTRIC_ALERT_ID
$env:CENTRIC_RAW_ALERT
```

## Retorno recomendado do script

Para o portal reconhecer confirmação automática, o script pode imprimir JSON na última linha:

```powershell
Write-Output '{"success":true,"message":"Ação executada com sucesso"}'
```
