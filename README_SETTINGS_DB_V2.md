# Centric v2 - Configurações em PostgreSQL

Esta versão remove a dependência de `settings.json` como fonte oficial da aba Configurações.

## O que mudou

- `/api/settings` agora lê e grava no PostgreSQL na tabela `app_settings`.
- Senhas, refresh tokens e client secrets são criptografados antes de serem gravados.
- Campos sensíveis continuam mascarados no frontend como `********`.
- Se o usuário salvar a tela deixando um campo sensível vazio ou mascarado, o valor anterior é preservado.
- O backend não grava mais as configurações em `backend/data/settings.json`.

## Tabela usada

```sql
app_settings (
  module,
  setting_key,
  setting_value,
  encrypted,
  created_at,
  updated_at
)
```

A implementação atual usa `module = 'core'` e salva as seções principais como chaves:

- `theme`
- `modules`
- `mail_server`
- `uem`

## Dados sensíveis criptografados

- `mail_server.password`
- `uem.api.client_secret`
- `uem.api.refresh_token`
- `uem.active_directory.domain_password`

A criptografia usa `APP_SECRET_KEY` do `.env`.

> Não troque `APP_SECRET_KEY` depois de salvar credenciais reais, ou os valores criptografados não poderão ser recuperados.

## Como testar em instalação limpa

```bash
docker compose down -v
docker compose up --build -d
docker compose logs -f app
```

Depois acesse:

```text
http://IP_DO_SERVIDOR:8443/login
```

Login inicial:

```text
admin
admin
```

Após a troca da senha inicial, acesse Configurações e salve os dados normalmente.

## Validação rápida no banco

```bash
docker compose exec db psql -U centric_user -d centric_db -c "select module, setting_key, encrypted from app_settings;"
```
