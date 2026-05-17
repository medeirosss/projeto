# Centric v2 - Autenticação AD e Roles

## O que foi adicionado

- Tela `/login`.
- Login via Active Directory usando LDAP/LDAPS Simple Bind.
- A senha do usuário final não é armazenada.
- Sessão via cookie HTTPOnly com JWT.
- Roles: `admin`, `operator`, `viewer`.
- Middleware protegendo páginas e APIs.
- Configurações > Usuários para liberar usuários/grupos do AD.

## Rotas públicas quando a licença está inválida

A regra de licença permanece igual:

- `/license/status`
- `/license/upload`
- `/health`
- arquivos estáticos da tela de licença

Com licença inválida, o login também fica bloqueado.

## Primeiro login / bootstrap

Para facilitar homologação limpa, se não existir nenhum usuário/grupo autorizado no banco, o primeiro usuário autenticado com sucesso no AD entra como `admin`.

Para desabilitar esse comportamento, adicione no `.env`:

```env
AUTH_BOOTSTRAP_EMPTY_ADMINS=false
```

## Roles

- `admin`: acesso total.
- `operator`: Centric, Relatórios, Ações e Alertas.
- `viewer`: Centric e Relatórios.

## Teste rápido

```bash
docker compose down
docker compose up --build -d
docker compose logs -f app
```

Acesse:

```text
http://IP_DO_SERVIDOR:8443/login
```

Use um usuário AD válido. Depois acesse:

```text
Configurações > Usuários
```

Cadastre os usuários ou grupos definitivos.
