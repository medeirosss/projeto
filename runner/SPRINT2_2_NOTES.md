# Sprint 2.2 — Asset Intelligence / Ativos

## Objetivo
Transformar a antiga área **Alvos** em uma visão consolidada de **Ativos**, sem alterar o mecanismo de descoberta validado na Sprint 2.1.1.

## Alterações
- Menu e página renomeados para **Ativos**.
- Nova rota preferencial `/ativos`, mantendo `/alvos` como alias compatível.
- Status visual alterado de **Online** para **Detectado**.
- Nome do ativo usa a prioridade: `display_name`, hostname, DNS e IP.
- Exibição de fabricante, origem, Runner, primeira e última descoberta.
- Pesquisa local por nome, hostname, DNS, IP, MAC, fabricante, origem e Runner.
- Ordenação por Status, Nome, IP, Fabricante, Primeira descoberta e Última descoberta.
- Campos persistentes adicionados: `display_name`, `asset_type` e `notes`.
- Nome amigável do Runner retornado pela API quando disponível.

## Fora do escopo
- Cálculo Online/Offline.
- Sistema operacional e fingerprint.
- Portas, serviços, vulnerabilidades e CVEs.
- Agente local e integração Endpoint Central.

## Migration
- `20260802_0017_asset_intelligence_ui.py`
- Novo Alembic head: `20260802_0017`
