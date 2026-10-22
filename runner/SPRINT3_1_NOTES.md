# Sprint 3.1 — Credential Engine

## Escopo
- Credenciais cadastradas em Configurações > Discovery > Credenciais.
- Segredos criptografados no PostgreSQL com Fernet; a chave mestra fica fora do banco (`APP_SECRET_KEY`).
- O scan seleciona opcionalmente uma credencial já cadastrada.
- No banco de jobs é persistido apenas `credential_id`; o segredo é injetado transitoriamente quando o Runner busca o job.
- Runner 2.13.0 com executor `credential_validate`.
- Máximo fixo de 2 tentativas por host.
- Windows: tentativa 1 WMI/CIM via DCOM; tentativa 2 WinRM.
- SSH: `hostname` via Paramiko.
- SNMP v2c: consulta `sysName.0`.
- Se o hostname do ativo estiver vazio e a autenticação retornar um nome, o Magi preenche `hostname` com origem `credential`.
- Falha de credencial não remove o ativo e não invalida Discovery/Service Discovery.

## Segurança
- A API de listagem nunca retorna o segredo em claro.
- `runner_jobs.payload` não armazena segredo em claro.
- O Runner redige o segredo antes de salvar `job.json` nos artefatos.
- Para produção, use HTTPS entre Runner e Magi, pois a credencial precisa viajar transitoriamente até o Runner.
- Defina `APP_SECRET_KEY` com uma chave forte e estável. Alterar a chave impede descriptografar credenciais já salvas.

## Limites da 3.1
- SNMP v3 e SSH key ficam para evolução posterior.
- A Sprint 3.2 utilizará as credenciais validadas para Deep Inventory.
