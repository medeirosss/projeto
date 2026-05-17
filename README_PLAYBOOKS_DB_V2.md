# Centric v2 — Ações > Scripts/Playbooks em PostgreSQL

Esta versão move o repositório de scripts/playbooks para o PostgreSQL.

## O que mudou

- `Ações > Repositório de scripts` lista playbooks da tabela `playbooks`.
- Upload de `.ps1` e `.sh` grava o conteúdo no banco.
- Exclusão faz soft delete (`enabled = false`).
- A execução manual e a execução por alerta continuam usando `script_name`, mas o backend materializa temporariamente o conteúdo do banco em `scripts/.runtime/` apenas para executar.
- A fonte oficial dos playbooks passa a ser o PostgreSQL, não a pasta `scripts/`.

## Tabela utilizada

```sql
playbooks
```

Campos principais:

```text
name
script_type
script_content
required_variables
metadata
enabled
```

## Metadados suportados no topo do script

```powershell
# @centric-name: Desabilitar usuário
# @centric-description: Desabilita usuário no AD
# @centric-required: username, target_ip
# @centric-optional: reason
# @centric-credential: ad_admin
```

ou em shell:

```bash
# @centric-name: Echo test
# @centric-required: hostname, ip
```

## Observação

A pasta `scripts/` pode continuar existindo para arquivos auxiliares e runtime, mas não é mais a fonte oficial do repositório de playbooks.
