# Magi Runner v2.10.7 - Console Installer

Esta versão volta ao método antigo: **sem Windows Service**.

O instalador faz:

- copia o Runner para `C:\Program Files\Magi\Runner`
- cria `.venv`
- instala dependências
- pergunta IP/FQDN/porta do Magi
- grava `settings.json` em UTF-8 sem BOM
- executa `--doctor`

## Instalação

Execute o PowerShell como Administrador:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install_runner.ps1
```

## Executar o Runner

```powershell
cd "C:\Program Files\Magi\Runner"
.\scripts\run_runner.ps1
```

## Alterar IP/FQDN do Magi depois

```powershell
cd "C:\Program Files\Magi\Runner"
.\scripts\configure_runner.ps1
```

## Diagnóstico

```powershell
cd "C:\Program Files\Magi\Runner"
.\scripts\doctor.ps1
```

## Remoção

```powershell
.\scripts\uninstall_runner.ps1
```
