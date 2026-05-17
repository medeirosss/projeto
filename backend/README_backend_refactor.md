# Backend refactor inicial

## Objetivo desta etapa
- Tirar responsabilidade de `main.py`
- Preparar o backend para módulos e configurações web
- Manter compatibilidade com os endpoints já usados pelo frontend

## Estrutura nova
- `backend/main.py`: bootstrap do FastAPI
- `backend/app/config.py`: paths e variáveis de ambiente
- `backend/app/routers/*`: rotas separadas por domínio
- `backend/app/services/*`: regras de negócio e acesso a dados

## Endpoints novos
- `GET /health`
- `GET /api/modules/status`
- `POST /api/token/refresh`
- `POST /api/scan/ad`
- `POST /api/scan/endpoint`

## Endpoints mantidos
- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/test-ad`
- `POST /api/settings/test-ec`
- `GET /api/dashboard`
- `POST /api/scan-now`
- relatórios em `/api/reports/*`
