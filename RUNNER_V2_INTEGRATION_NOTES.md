# Magi - Runner v2 integration patch

Esta versão adiciona a API necessária para o Magi Runner v2.10.7 registrar, enviar heartbeat, buscar jobs e devolver resultados.

## Endpoints adicionados

- `GET /api/runners/ping`
- `POST /api/runners/register`
- `POST /api/runners/heartbeat`
- `GET /api/runners/jobs/next`
- `POST /api/runners/jobs/{job_id}/result`

Também foi mantida compatibilidade com `/api/runner/*` para a tela atual de Configurações.

## Banco de dados

Foi adicionada a migration SQL:

- `backend/migrations/20260706_0014_runner_v2_api.sql`

O backend também executa `ensure_runner_schema()` no startup para normalizar ambientes que já tinham tabelas antigas de runner.

## Teste rápido

No backend:

```bash
curl http://localhost:8000/api/runners/ping
```

No Runner:

```powershell
cd "C:\Program Files\Magi\Runner"
.\scripts\configure_server.ps1 -ServerUrl "http://IP_DO_MAGI:8000" -Online
.\scripts\run_runner.ps1
```

Na interface do Magi, veja em `Configurações > Runners`.
