# Dashboard AD x Endpoint Central

## Execução
```bash
cd backend
python -m pip install -r requirements.txt
copy .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Endereços
- Home: http://localhost:8000/
- Configurações: http://localhost:8000/configuracoes
- Instalador: http://localhost:8000/instalador

## Implementado
- log por execução com nome `log(AAAAMMDD_HHMMSS).log`
- log contendo somente HTTP status e total de máquinas do Endpoint Central
- paginação da API pronta para 25, 50, 100 e 1000
- modo debug persistido em arquivo de parâmetros
- configurações persistidas em `backend/data/settings.json`
- senha do AD salva criptografada via PowerShell
- home com layout inspirado na tela inicial do Endpoint Central
- tabelas paginadas com 15 linhas por página
- auto refresh configurável em 1, 3 ou 6 horas


## Atualizações
- JSON filtrado salvo apenas com: full_name, mac, ip, agent_logged_on_users, resource_id, live_status.
- Nova aba Relatórios.
- Primeiro relatório: Usuários ativos no ambiente.


## Atualização da estrutura

### Novidades
- Relatório **Scans** para comparar AD, Endpoint Central e múltiplos CSVs
- Pasta **compare/** na raiz do projeto
- Busca por hostname com ícone de lupa nos relatórios
- Exportação do resultado do compare em CSV

### Requisito adicional
Instale também:

```bash
pip install -r backend/requirements.txt
```

### Estrutura relevante
```
centric_updated_project/
├─ backend/
├─ frontend/
└─ compare/
```
