# Credenciais em PostgreSQL — v2

Nesta versão, o **Repositório de credenciais** permanece como uma opção dentro da aba **Ações**.

## O que mudou

- A rota `/api/actions/credentials` agora usa PostgreSQL.
- A tabela usada é `stored_credentials`.
- A senha/segredo é salvo em `secret_encrypted` com criptografia via `APP_SECRET_KEY`.
- A API nunca retorna a senha em texto claro para o frontend.
- Quando a credencial é usada na execução de playbook, o backend decripta apenas em runtime e injeta nas variáveis de ambiente do processo.
- Exclusão é feita como soft delete (`enabled = false`).

## Endpoints mantidos

```text
GET    /api/actions/credentials
POST   /api/actions/credentials
DELETE /api/actions/credentials/{id}
```

## Variáveis injetadas em playbooks

```text
CENTRIC_EXEC_CREDENTIAL_NAME
CENTRIC_EXEC_USERNAME
CENTRIC_EXEC_PASSWORD
```

## Observação

Credenciais não são uma aba própria. Elas continuam no menu lateral da aba **Ações**, como **Gerais > Repositório de credenciais**.
