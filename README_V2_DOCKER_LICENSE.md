# Centric Portal v2 - Baseline limpa com Docker, PostgreSQL e Licenciamento

Esta versão adiciona a base da instalação limpa:

- `docker-compose.yml` com `app` + `db`
- PostgreSQL isolado, sem porta publicada para o host
- `db/init.sql` criando a baseline limpa do banco
- licença offline assinada
- validação de licença no startup
- revalidação automática a cada 1 hora
- tela/endpoints públicos mínimos para licença
- middleware global bloqueando a aplicação quando a licença está ausente, inválida ou expirada

## Endpoints liberados sem licença válida

Quando a licença está inválida, somente estes caminhos ficam disponíveis:

```text
/license
/license/status
/license/upload
/health
```

Todo o restante retorna bloqueio de licença.

## Como testar

1. Copie o `.env.example` para `.env`:

```bash
cp .env.example .env
```

2. Ajuste pelo menos estes valores:

```env
POSTGRES_PASSWORD=uma_senha_forte
DATABASE_URL=postgresql+psycopg2://centric_user:uma_senha_forte@db:5432/centric_db
APP_SECRET_KEY=<chave_fernet>
EXPECTED_AD_DOMAIN=labdaniel.local
```

Para gerar uma chave Fernet:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

3. Suba a stack:

```bash
docker compose up --build
```

4. Acesse:

```text
http://localhost:8443/license/status
http://localhost:8443/
```

## Licença de desenvolvimento

Este pacote contém uma licença DEV em:

```text
license/license.json
```

E uma pasta de simulação de autoridade emissora:

```text
license_authority_DEV_DO_NOT_SHIP/
```

Essa pasta contém chave privada apenas para teste. **Não enviar para cliente.**

Em produção, a chave privada deve ficar somente em ambiente interno da Centric. O cliente recebe apenas o `license.json` assinado e a aplicação com a chave pública.

## Reset limpo do banco

O `db/init.sql` só roda automaticamente quando o volume do PostgreSQL é criado pela primeira vez.

Para apagar tudo e criar do zero:

```bash
docker compose down -v
docker compose up --build
```

## Observação importante

Esta entrega cria a fundação da v2: containers, banco limpo e licenciamento modular.
Os routers antigos ainda existem no projeto e serão conectados aos repositories PostgreSQL nas próximas etapas.


## Ajuste AD no container Linux

Esta versão não usa mais PowerShell/RSAT para o módulo de AD. O scan/teste de AD usa LDAP/LDAPS via Python (`ldap3`), adequado para execução em container Linux.

Configuração esperada em homologação:

```env
EXPECTED_AD_DOMAIN=labdaniel.local
```

Na tela de Configurações, o campo `dc_host` pode ser informado como:

```text
dc.labdaniel.local
ldaps://dc.labdaniel.local:636
ldap://dc.labdaniel.local:389
```

O usuário de domínio pode ser informado como:

```text
LABDANIEL\usuario
usuario@labdaniel.local
usuario
```

Se informar apenas `usuario`, a aplicação monta `usuario@EXPECTED_AD_DOMAIN`.

Recomendação: usar LDAPS/636 sempre que possível.


## Active Directory LDAP/LDAPS

Na tela **Configurações > Active Directory**, o acesso ao AD agora é configurável:

- LDAP sem SSL/TLS: porta 389
- LDAPS com SSL/TLS: porta 636

Para ambientes de homologação ou clientes que ainda não possuem LDAPS corretamente configurado, use LDAP 389. Para produção, recomenda-se LDAPS 636.
