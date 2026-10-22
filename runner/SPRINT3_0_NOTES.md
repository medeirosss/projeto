# Sprint 3.0 — Service Discovery Engine

## Objetivo
Adicionar descoberta de serviços como etapa opcional posterior ao Discovery/Enrichment, executada somente nos hosts confirmados.

## Fluxo
Discovery -> DNS -> Fingerprint/Classificação -> Service Discovery -> Inventário.

## Runner
- Versão: 2.12.0
- Novo executor: `service_discovery`
- Usa Nmap já instalado no host Windows.
- Perfil inicial controlado pelo Magi: `-Pn -n -sV --version-light --top-ports 100 --open -T4 --max-retries 1`.
- O usuário não fornece argumentos arbitrários do Nmap.

## Banco
Migration `20260807_0020`.
Novas estruturas:
- `asset_services`: visão atual dos serviços abertos por ativo.
- `asset_service_observations`: histórico das observações.
- `service_discovery_jobs`: vínculo entre o pipeline e os jobs do Runner.
- Campos de progresso em `discovery_runs`.
- `service_discovery_enabled` em `discovery_scans`.

## Service Knowledge Base
Arquivo `backend/config/service_knowledge.yaml` com nomes e categorias amigáveis para serviços comuns. É uma base de conhecimento de serviços, não uma base de vulnerabilidades.

## Interface
- Checkbox para habilitar Service Discovery ao criar um scan.
- Pipeline visual mostra o andamento da nova etapa.
- Contagem de serviços na lista de Ativos.
- Clique na contagem abre os serviços atuais do ativo.
- Falhas de Service Discovery são visíveis por ativo e não removem o ativo do inventário.

## Fora do escopo
Credential Engine, Deep Inventory, Exposure/CVE, exploração e Online/Offline.
