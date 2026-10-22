# Magi Atomic - Etapa 3C Runner Dry Run + Inventário de Runners

## O que foi adicionado

1. Tela em **Configurações > Runners** para visualizar runners registrados:
   - runner_id
   - status
   - hostname
   - IP
   - sistema operacional
   - modo Atomic
   - jobs abertos
   - último heartbeat

2. Endpoint administrativo:

```text
GET /api/runner/runners
```

3. Registro/heartbeat do Runner agora aceita `metadata`, incluindo:

```json
{
  "ip_address": "192.168.0.10",
  "os": "Windows...",
  "runner_version": "3C-preview-20260528",
  "atomic_mode": "dry_run"
}
```

4. Runner de referência atualizado para Etapa 3C.

## Modos do Runner

### Modo seguro padrão

```powershell
$env:MAGI_ATOMIC_RUNNER_MODE="dry_run"
```

Neste modo, nenhum comando PowerShell Atomic é executado. O Runner apenas confirma que recebeu o job.

### Modo preview controlado

```powershell
$env:MAGI_ATOMIC_RUNNER_MODE="execute_preview"
$env:MAGI_ATOMIC_PREVIEW_ACTION="show_details"
```

Neste modo, o Runner executa apenas:

```powershell
Invoke-AtomicTest Txxxx -TestNumbers N -ShowDetailsBrief
```

Isso não executa o teste Atomic real. Apenas mostra detalhes do teste.

## Pré-requisito no Windows Runner

```powershell
Install-Module Invoke-AtomicRedTeam -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
```

## Validação

1. Inicie o Runner.
2. Acesse **Configurações > Runners**.
3. Confirme que o runner aparece como `online`.
4. Em **Validações**, aprove um teste de baixo risco.
5. Prepare a execução.
6. Envie ao Runner.
7. Verifique o resultado em `atomic_execution_jobs`.

## Observação de segurança

Esta etapa ainda NÃO libera execução real de Atomic tests. Ela valida apenas o fluxo de preview/dry-run.
