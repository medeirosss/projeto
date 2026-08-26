# Sprint 2.3 — Enrichment Engine

Esta versão adiciona um pipeline de enriquecimento após cada descoberta. A primeira etapa implementada é o fingerprint de tipo do ativo, baseado em regras externas no arquivo `backend/config/fingerprints.yaml`.

## Escopo
- Classificação de ativo sem agente ou credenciais.
- Tipos iniciais: workstation, server, printer, firewall, network_device, NAS, hypervisor, virtual_machine e unknown.
- Confiança, regra aplicada, motivos e data do fingerprint.
- Regras editáveis sem recompilar o backend.
- Coluna Tipo na tela Ativos.

## Fora do escopo
Sistema operacional, portas, serviços, CVEs e estado Online/Offline.
