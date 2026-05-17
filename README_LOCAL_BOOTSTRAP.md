# Centric v2 - Login local inicial

Esta versão adiciona um usuário local inicial para bootstrap da aplicação.

## Primeiro acesso

- Usuário: `admin`
- Senha: `admin`

Após o primeiro login, a aplicação redireciona obrigatoriamente para `/change-password`.
A senha local não é armazenada em texto claro. O banco grava apenas hash PBKDF2-SHA256 com salt.

## Fluxo

1. Subir containers.
2. Acessar `/login`.
3. Entrar com `admin/admin`.
4. Trocar a senha local obrigatoriamente.
5. Configurar AD em Configurações.
6. Cadastrar usuários/grupos autorizados do AD.

## Recriar ambiente limpo

Se precisar testar o primeiro login novamente:

```bash
docker compose down -v
docker compose up --build -d
```

`down -v` apaga o volume do PostgreSQL.
