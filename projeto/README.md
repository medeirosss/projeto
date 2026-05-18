# Sistema Magi

Sistema Magi é uma plataforma modular para operação, alertas, automação e relatórios, com foco em SOC/NOC, integração com ferramentas externas e execução controlada de playbooks.

> Nome atual do projeto: **Sistema Magi**. Referências antigas a “Centric” podem aparecer apenas como legado visual/código histórico.

---

## 1. Status atual do projeto

### Concluído

- Deploy por imagem Docker publicada no **GHCR**.
- Build automatizado via **GitHub Actions**.
- Instalação validada com Docker Compose.
- Deploy validado em Windows.
- PostgreSQL como banco principal.
- Licenciamento offline por `license.json` assinado.
- Nova chave pública de licença aplicada na aplicação.
- Gerador externo de licença validado com validade máxima de 183 dias.
- Layout visual padronizado nas principais abas.
- Dark mode global preparado.
- Branding preparado para customização de logo, nome e cor principal.
- Normalizador inicial de alertas implementado.

### Pendências técnicas conhecidas

Estas correções devem entrar na próxima build:

- Implementar migrations com **Alembic**.
- Incluir criação automática da tabela `login_audit_log`.
- Padronizar `APP_SECRET_KEY` no `.env.example` e no pacote de deploy.
- Remover dependência de ajuste manual no banco em primeira instalação.

---

## 2. Roadmap atualizado

1. **Deploy / imagem / instalação** — concluído.
2. **Padronização visual** — concluído.
3. **Enriquecimento de alertas** — etapa atual.
4. **Testes automáticos**.
5. **Integração SIEM**.
6. **XDR / SOAR-lite**.
7. **Licenciamento completo final**.

Itens futuros:

- Escalabilidade.
- Vulnerabilidade em nós de rede via SNMP + base de CVEs.
- IA local com Ollama/LLM como última etapa.

---

## 3. Estrutura principal

```text
.
├── backend/
│   ├── main.py
│   └── app/
│       ├── auth/
│       ├── database/
│       ├── license/
│       ├── repositories/
│       ├── routers/
│       ├── security/
│       └── services/
├── db/
│   └── init.sql
├── frontend/
├── scripts/
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 4. Execução via Docker Compose

A aplicação é empacotada como imagem publicada no GitHub Container Registry.

Exemplo de serviço backend:

```yaml
backend:
  image: ghcr.io/medeirosss/magi-backend:v1.0.5
  container_name: magi_backend
  restart: unless-stopped
  depends_on:
    postgres:
      condition: service_healthy
  env_file:
    - .env
  ports:
    - "8000:8443"
```

A aplicação dentro do container escuta em:

```text
0.0.0.0:8443
```

No host, o acesso padrão validado é:

```text
http://localhost:8000
```

---

## 5. Variáveis de ambiente importantes

Exemplo mínimo:

```env
APP_ENV=production
APP_PORT=8000

POSTGRES_DB=magi
POSTGRES_USER=magi
POSTGRES_PASSWORD=Troque_Essa_Senha_Forte

DATABASE_URL=postgresql+psycopg2://magi:Troque_Essa_Senha_Forte@postgres:5432/magi

APP_SECRET_KEY=troque_este_valor_por_uma_chave_grande
ENCRYPTION_KEY=troque_este_valor_por_uma_chave_grande

LICENSE_FILE=/app/license/license.json
LICENSE_PUBLIC_KEY_FILE=app/license/public_key.pem
LICENSE_ENFORCEMENT=true
LICENSE_CHECK_INTERVAL_SECONDS=3600
```

> Atenção: `APP_SECRET_KEY` é usado para JWT e criptografia de dados sensíveis. Não troque essa chave depois de salvar credenciais reais, a menos que exista um processo de rotação/migração.

---

## 6. Deploy de cliente

O pacote de deploy deve conter:

```text
deploy/
├── docker-compose.yml
├── .env.example
├── install-linux.sh
├── install-windows.ps1
└── README_DEPLOY.md
```

Fluxo validado:

1. Instalar/validar Docker.
2. Executar `docker compose pull`.
3. Executar `docker compose up -d`.
4. Acessar `/license`.
5. Enviar `license.json`.
6. Acessar `/login`.

---

## 7. GitHub Actions / GHCR

Workflow atual esperado:

```text
.github/workflows/build-backend.yml
```

A imagem é publicada em:

```text
ghcr.io/medeirosss/magi-backend
```

Fluxo de nova versão:

```powershell
git add .
git commit -m "Mensagem da alteração"
git push

git tag v1.0.X
git push origin v1.0.X
```

Depois, atualizar no `docker-compose.yml`:

```yaml
image: ghcr.io/medeirosss/magi-backend:v1.0.X
```

---

## 8. Licenciamento

O Sistema Magi usa licença offline assinada.

### Fluxo

```text
Gerador externo + private_key.pem
        ↓
license.json assinado
        ↓
Cliente faz upload em /license
        ↓
Aplicação valida com public_key.pem
```

A chave privada deve ficar fora da aplicação e fora do Git.

A aplicação valida a licença usando:

```text
backend/app/license/public_key.pem
```

O arquivo de licença dentro do container fica em:

```text
/app/license/license.json
```

### Endpoints públicos de licença

Mesmo com licença inválida, os seguintes caminhos ficam acessíveis:

```text
/license
/license/status
/license/upload
/health
```

### Campos esperados no license.json

```json
{
  "license_id": "MAGI-...",
  "customer_id": "CLIENTE-001",
  "customer_name": "Cliente Exemplo",
  "domain_name": "cliente.local",
  "license_type": "commercial",
  "license_mode": "offline",
  "expires_at": "2026-12-31",
  "modules": {
    "centric": true,
    "alerts": true,
    "actions": true,
    "reports": true,
    "settings": true
  },
  "max_users": 100,
  "max_endpoints": 500,
  "signature": "..."
}
```

---

## 9. Autenticação

### Login local inicial

Para bootstrap:

```text
Usuário: admin
Senha: admin
```

Após o primeiro login, a aplicação pode redirecionar para troca de senha.

### Login AD

A aplicação também possui suporte a autenticação via Active Directory usando LDAP/LDAPS.

Roles previstas:

```text
admin
operator
viewer
```

---

## 10. Banco de dados

O PostgreSQL é a fonte oficial para:

- Configurações.
- Credenciais.
- Scripts/playbooks.
- Execuções.
- Alertas.
- Histórico de alertas.
- Relatórios e scans.
- Uploads CSV de comparação.
- Autenticação local/roles.
- Status de licenciamento.

Continuam em arquivo por decisão arquitetural:

- Logs operacionais.
- Arquivo de licença.
- Chave pública da licença.
- Assets estáticos.
- Scripts temporários materializados em runtime.

---

## 11. Configurações

A aba Configurações grava no PostgreSQL, principalmente na tabela:

```text
app_settings
```

Dados sensíveis devem ser criptografados, incluindo:

- senha de e-mail;
- `client_secret`;
- `refresh_token`;
- senha do usuário de domínio/AD.

Também foi adicionada base para **branding**, permitindo no futuro controlar pela UI:

- nome da marca;
- logo;
- cor principal/accent.

---

## 12. Ações e playbooks

A aba Ações contempla:

- Repositório de credenciais.
- Repositório de scripts/playbooks.
- Execução manual.
- Execução por alerta.
- Histórico de execuções.

Playbooks são armazenados no PostgreSQL e materializados temporariamente em:

```text
scripts/.runtime/
```

Metadados suportados no topo do script:

```powershell
# @centric-name: Desabilitar usuário
# @centric-description: Desabilita usuário no AD
# @centric-required: username, target_ip
# @centric-optional: reason
# @centric-credential: ad_admin
```

---

## 13. WinRM / PowerShell remoto

Para scripts que dependem de Windows/AD, o Magi pode executar playbooks via WinRM.

Uso típico:

- Módulo ActiveDirectory/RSAT.
- Ações em AD.
- Execução PowerShell remota.
- Operações que não funcionam dentro do container Linux.

Produção recomendada:

- WinRM HTTPS 5986.
- Certificado válido.
- `AllowUnencrypted=false`.
- Conta com privilégio mínimo.

---

## 14. Alertas

### Status

```text
1 = novo alarme
2 = conhecido
3 = finalizado
```

### Fonte

Alertas podem chegar por webhook, por exemplo:

```text
POST /api/actions/inbound-alert
```

O webhook pode ser protegido por:

```text
X-Centric-Webhook-Token
```

e por lista de IPs/fontes confiáveis.

---

## 15. Normalização de alertas

Foi adicionada uma primeira versão de normalização de payloads inbound.

Objetivo:

- Receber payloads de ADAudit, SIEM ou webhook genérico.
- Converter campos variados para um modelo interno comum.
- Preservar payload original.
- Adicionar contexto normalizado.

Campos tratados:

```text
event_number / event_id / EventID
account_name / username / target_user
caller_user_name / actor / subject_user
source_ip / target_ip / hostname
```

Eventos iniciais de referência:

```text
4625 = falha de login
4720 = criação de usuário
4728 = membro adicionado a grupo global
4732 = membro adicionado a grupo local
```

O payload normalizado deve ser usado para enriquecer:

- MITRE.
- NIST.
- severidade.
- usuário alvo.
- executor.
- IP/host.
- origem.

---

## 16. Relatórios e scans

Relatórios e scans usam PostgreSQL como fonte oficial.

Tabelas principais:

```text
scan_snapshots
report_files
scan_compare_runs
```

A exportação CSV pode ser gerada em memória e entregue para download, sem depender de arquivos fixos como fonte oficial.

---

## 17. Layout e branding

Padronização visual concluída para as abas principais.

Inclui:

- cabeçalho unificado;
- botões superiores padronizados;
- dark mode global;
- contadores de alertas com cores;
- branding preparado;
- logo e cor principal customizáveis.

Padrão atual:

- logo Centric;
- cor roxa/accent.

A customização completa deve ser mantida em Configurações.

---

## 18. Testes úteis

### Ver logs do backend

```powershell
docker compose logs -f backend
```

### Ver containers

```powershell
docker compose ps
```

### Reiniciar backend

```powershell
docker compose restart backend
```

### Recriar ambiente limpo

```powershell
docker compose down -v
docker compose up -d
```

### Testar endpoints básicos

```powershell
curl http://localhost:8000/health
curl http://localhost:8000/license/status
```

---

## 19. Próxima build recomendada

A próxima build deve focar em maturidade operacional:

1. Implementar Alembic.
2. Criar migration da tabela `login_audit_log`.
3. Garantir `APP_SECRET_KEY` no `.env.example`.
4. Garantir primeira instalação sem SQL manual.
5. Continuar enriquecimento de alertas.
