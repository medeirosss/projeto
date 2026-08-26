# Magi - Alembic/Migrations

Este pacote muda o fluxo do banco para o modelo correto:

- Alembic é a fonte oficial do schema.
- O arquivo `db/init.sql` deixa de ser montado no PostgreSQL pelo `docker-compose.yml`.
- O backend copia `alembic.ini` e a pasta `alembic/` para a imagem.
- Ao iniciar, o backend espera o PostgreSQL e executa `alembic upgrade head` automaticamente.

## Reset limpo em ambiente de desenvolvimento

```bash
docker compose down -v
docker compose up -d --build
```

## Verificar migrations

```bash
docker logs magi_backend --tail=80
# ou, se o container estiver com nome antigo:
docker logs centric_app --tail=80
```

A linha esperada é semelhante a:

```text
Running database migrations...
Starting Magi backend...
```

## Login inicial

Após o banco limpo, o login inicial continua:

```text
admin / admin
```

O usuário local é criado pela migration baseline com `must_change_password = true`.

## Rodar migration manualmente

```bash
docker exec -it magi_backend alembic -c /app/alembic.ini upgrade head
```

Se o container estiver com nome antigo:

```bash
docker exec -it centric_app alembic -c /app/alembic.ini upgrade head
```
