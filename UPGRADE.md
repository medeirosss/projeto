# Upgrade para 0.8.0-validation-history

## Banco de dados
Não há migration obrigatória nova nesta sprint.

A sprint utiliza as tabelas já existentes:
- `atomic_execution_jobs`
- `atomic_tests`
- `runner_jobs`

## Atualização recomendada em homologação

```powershell
docker compose down
docker compose build --no-cache
docker compose up -d
```

Depois valide os logs:

```powershell
docker logs -f magi_backend
```

## Pontos de atenção
- Garanta que as migrations anteriores já foram aplicadas.
- Garanta que o frontend carregado pelo navegador não esteja em cache. Em caso de dúvida, abra em guia anônima ou force reload com Ctrl+F5.
