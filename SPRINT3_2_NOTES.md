# Sprint 3.2 — Deep Inventory & Process Intelligence

## Escopo
- Deep Inventory opcional por scan, executado somente após uma credencial validada.
- Intervalos de coleta permitidos: 10, 30 ou 60 minutos.
- O Magi mantém somente o snapshot atual de hardware/sistema. Não armazena séries de CPU/RAM/disco.
- Histórico é criado somente quando um componente estrutural muda (fabricante, modelo, serial, CPU, quantidade de CPU lógica/cores, RAM instalada ou discos).
- Process Knowledge Base administrável pelo técnico.
- O Runner coleta processos, mas o backend persiste somente processos que casam com regras configuradas.
- Findings de processo guardam primeira/última detecção e se continuam presentes.

## Runner
Versão 2.14.0, executor `deep_inventory`.

Windows usa CIM/WMI DCOM com a credencial já validada. SSH possui coleta básica para Linux. SNMP permanece reservado para evolução do Deep Inventory de equipamentos de rede.

## Banco
Migration `20260810_0023`.
Tabelas novas:
- `asset_inventory_snapshot`
- `asset_hardware_changes`
- `process_knowledge_rules`
- `asset_process_findings`
- `deep_inventory_jobs`

## Segurança e retenção
- Segredos continuam criptografados no PostgreSQL e são injetados transitoriamente no job.
- `runner_jobs` guarda somente `credential_id`.
- Não há armazenamento de métricas históricas de performance nesta sprint.
