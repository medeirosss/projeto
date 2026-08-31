# Checklist - Golden Image Técnica do Runner v2

## Instalação

- [ ] Executar `scripts/install.ps1` ou `scripts/install.sh`.
- [ ] Copiar `settings.example.json` para `settings.json`.
- [ ] Ajustar `server_url`, `registration_token`, `offline_mode` e `allowed_executors`.
- [ ] Executar `scripts/doctor.ps1` ou `scripts/doctor.sh`.

## Teste local

- [ ] Executar `scripts/run.ps1` ou `scripts/run.sh`.
- [ ] Confirmar criação de `runner_data/logs/runner.log`.
- [ ] Confirmar criação de evidências em `runner_data/jobs`.
- [ ] Confirmar geração de ZIP de evidências por job.

## Serviço

- [ ] Instalar serviço Windows com `scripts/install_service.ps1` como Administrador.
- [ ] Iniciar serviço com `scripts/start_service.ps1`.
- [ ] Validar `runner_data/health.json`.
- [ ] Parar serviço com `scripts/stop_service.ps1`.

## Segurança

- [ ] Confirmar `server_url` com HTTPS.
- [ ] Confirmar `verify_tls=true`.
- [ ] Confirmar `offline_mode=false` em produção.
- [ ] Confirmar conta de serviço dedicada.
- [ ] Confirmar executores permitidos conforme política do cliente.
- [ ] Executar `scripts/security_report.ps1` e guardar saída no registro de implantação.

## Update

- [ ] Validar `release_manifest.example.json`.
- [ ] Testar `scripts/check_update.ps1`.
- [ ] Validar rollback em ambiente de homologação.
