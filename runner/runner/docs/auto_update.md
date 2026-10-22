# Magi Runner v2 - Sprint 7 Auto Update

## Objetivo

A Sprint 7 adiciona atualização controlada do Runner sem mexer no core de execução dos jobs.

Recursos incluídos:

- versão centralizada em `magi_runner/core/version.py`;
- checagem de manifesto de release;
- download do pacote `.zip`;
- validação SHA-256;
- backup local antes da troca;
- rollback local;
- modo manual por CLI/scripts;
- modo automático opcional durante o loop do Runner.

## Campos novos do `settings.json`

```json
{
  "update_enabled": false,
  "update_manifest_url": "./release_manifest.example.json",
  "update_check_interval_seconds": 3600,
  "update_auto_apply": false,
  "update_download_timeout_seconds": 120
}
```

Por padrão, o update vem desativado. Para laboratório, use um manifesto local. Para produção, a URL esperada pode ser exposta pelo backend:

```text
GET /api/runners/updates/manifest
```

## Formato do manifesto

```json
{
  "version": "2.7.1",
  "package_url": "https://magi-server/downloads/magi_runner_v2_2.7.1.zip",
  "sha256": "<sha256 do zip>",
  "mandatory": false,
  "notes": "Correções e melhorias da release"
}
```

## Comandos Windows

```powershell
.\scripts\check_update.ps1
.\scripts\apply_update.ps1
.\scripts\rollback_update.ps1
```

## Comandos Linux

```bash
./scripts/check_update.sh
./scripts/apply_update.sh
./scripts/rollback_update.sh
```

## CLI direta

```bash
python -m magi_runner --version
python -m magi_runner --config settings.json --check-update
python -m magi_runner --config settings.json --apply-update
python -m magi_runner --config settings.json --rollback-update
```

## Auto update

Para habilitar update automático:

```json
{
  "update_enabled": true,
  "update_auto_apply": true,
  "update_check_interval_seconds": 3600
}
```

Quando uma atualização é aplicada, o Runner grava `runner_data/updates/pending_restart.json` e encerra o loop. Em serviço Windows ou `systemd`, o serviço deve reiniciar automaticamente conforme a política configurada na Sprint 6.

## Segurança

A Sprint 7 valida integridade com SHA-256. Na Sprint 8, o pacote deve evoluir para assinatura digital do manifesto/pacote, mTLS/JWT e hardening completo.
