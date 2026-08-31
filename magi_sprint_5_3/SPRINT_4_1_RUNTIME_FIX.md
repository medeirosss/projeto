# MAGI Sprint 4.1 — Runtime Fix

- Nuclei v3.8.0 provisionado automaticamente pelo instalador do Runner.
- Runtime isolado em `tools\nuclei\nuclei.exe`.
- Templates provisionados em `tools\nuclei\templates`.
- `engine_unavailable`, `template_unavailable` e `target_unreachable` são estados distintos.
- O Runner continua funcional caso o provisioning online falhe.
- Provisionamento offline continua suportado.
