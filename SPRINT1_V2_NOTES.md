# Magi — Sprint 1 v2

## Entrega

A área Alvos foi dividida em:

- Máquinas descobertas: lista apenas hosts confirmados pelo Nmap.
- Scan: criação, execução, agendamento, pausa e exclusão de scans.

## Critério de confirmação

O backend não salva o IP informado pelo usuário. Ele persiste somente hosts retornados como `up` pelo Nmap com motivo de resposta direta aceito, descartando estados presumidos como `user-set`.

## Agendamento

- Execução manual ou por intervalo.
- Intervalo mínimo: 15 minutos.
- Configurações persistidas no PostgreSQL.
- O scheduler consulta scans vencidos a cada 30 segundos por padrão.
- Variável opcional: `DISCOVERY_SCHEDULER_INTERVAL_SECONDS`.

## Atualização

1. Publique a nova imagem usando o Dockerfile que contém Nmap.
2. Confirme `NET_RAW` no serviço backend do Compose.
3. Suba a aplicação normalmente.
4. Confirme nos logs a migration `20260726_0014`.
5. Acesse `/alvos` e use o submenu Scan.

## Testes mínimos

1. Criar um scan manual para um IP existente.
2. Confirmar que o host aparece em Máquinas descobertas.
3. Criar um scan para um IP inexistente.
4. Confirmar que nenhum alvo é criado.
5. Criar um scan CIDR e validar duração e contagem.
6. Configurar intervalo de 15 minutos e confirmar próxima execução.
7. Pausar e reativar o agendamento.
8. Excluir um host e confirmar que ele reaparece após responder a um novo scan.
9. Excluir um scan mantendo os alvos.
10. Excluir outro scan removendo alvos exclusivos.
