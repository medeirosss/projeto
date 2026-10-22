# Magi Runner v2 - Sprint 8 Hardening

## Objetivo

Esta sprint fecha o Runner v2 como primeira Golden Image técnica para testes reais. O foco é reduzir risco operacional antes de instalar o Runner em ambientes de cliente.

## Novos comandos

### Doctor

Executa validações locais de pré-requisito, configuração e segurança.

Windows:

```powershell
.\scripts\doctor.ps1
```

Linux:

```bash
./scripts/doctor.sh
```

Também pode ser chamado diretamente:

```bash
python -m magi_runner --doctor --config ./settings.json
```

### Security report

Gera um relatório da configuração com dados sensíveis mascarados.

Windows:

```powershell
.\scripts\security_report.ps1
```

Linux:

```bash
./scripts/security_report.sh
```

Direto pelo Python:

```bash
python -m magi_runner --security-report --config ./settings.json
```

## Validações aplicadas

O Runner agora bloqueia inicialização se encontrar erros críticos de configuração:

- `settings.json` inexistente ou inválido.
- `runner_name` fora do padrão permitido.
- modo online sem `registration_token` ou `runner_secret`.
- `allowed_executors` vazio.
- intervalos ou timeouts inválidos.

O Runner gera alerta, mas não bloqueia, para riscos operacionais:

- `server_url` sem HTTPS em modo online.
- `verify_tls=false` em modo online.
- executor Python habilitado.
- executor Atomic habilitado.

## Recomendações para produção

1. Usar HTTPS no backend Magi.
2. Manter `verify_tls=true`.
3. Criar um token individual por Runner.
4. Executar o serviço com conta dedicada e privilégio mínimo possível.
5. Habilitar somente os executores necessários no ambiente.
6. Não deixar `offline_mode=true` em produção.
7. Restringir permissão do diretório `runner_data`.
8. Coletar `runner_data/logs/runner.log` em troubleshooting.
9. Usar auto update apenas com manifesto e pacote assinados/validados por hash.

## Status da Sprint 8

Implementado:

- versão `2.8.0`;
- validação rígida de configuração;
- relatório de segurança com redaction de secrets;
- comando `--doctor`;
- comando `--security-report`;
- scripts Windows/Linux para validação;
- documentação de hardening;
- limpeza de artefatos locais no pacote final.

Ainda recomendado para uma próxima fase:

- assinatura digital real do pacote de update;
- mTLS entre Runner e backend;
- instalador MSI/EXE;
- pipeline CI para build e release.
