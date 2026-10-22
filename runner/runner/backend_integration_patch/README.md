# Magi Runner v2.9 — Backend Integration Patch

Este patch adiciona ao backend do Magi os endpoints necessários para integração real do Runner v2.

## Arquivos

- `backend/app/api/runner_v2.py`
- `backend/app/models/runner_v2.py`
- `backend/app/schemas/runner_v2.py`
- `backend/app/services/runner_v2_security.py`
- `backend/alembic/versions/002_runner_v2.py`
- `sql/002_runner_v2.sql`

## Variável obrigatória no backend

Adicione no `docker-compose.yml` ou `.env` do backend:

```env
MAGI_RUNNER_REGISTRATION_TOKEN=TOKEN_FORTE_AQUI
```

Este mesmo token deve ser colocado no Runner em `registration_token`.

## Wiring no FastAPI

No arquivo onde o `FastAPI()` é criado:

```python
from app.api.runner_v2 import router as runner_v2_router
app.include_router(runner_v2_router)
```

## Banco

Aplicar SQL direto:

```bash
psql -U magi -d magi -f sql/002_runner_v2.sql
```

ou ajustar `down_revision` da migration Alembic e executar `alembic upgrade head`.

## Endpoints usados pelo Runner

- `GET /api/runners/ping`
- `POST /api/runners/register`
- `POST /api/runners/heartbeat`
- `GET /api/runners/jobs/next`
- `POST /api/runners/jobs/{job_id}/result`

## Endpoints administrativos temporários

- `GET /api/runners`
- `GET /api/runners/jobs`
- `POST /api/runners/jobs`

Proteja esses endpoints com a autenticação administrativa do Magi antes de produção.
