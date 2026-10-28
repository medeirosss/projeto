# MAGI 6.2.3 — Campaign UI & Evidências

Base: MAGI 6.2.2 fornecida pelo usuário.

- Filtro textual local por IP, hostname, protocolo, job e diagnóstico na aba Evidências.
- Filtro por protocolo registrado e opção de exportar CSV (UTF-8 BOM, aspas escapadas).
- CSV respeita os filtros ativos; inclui IP, hostname quando disponível, origem, protocolo, ciclo, Runner Job, hop, classificação e diagnóstico.
- Ativos conhecidos sem alcance confirmado são diferenciados de falhas protocoladas.
- Mantidos backend, Runner, banco e demais funcionalidades da 6.2.2.

Validação: sintaxe JavaScript e integridade do pacote verificadas; teste integrado Docker e teste funcional no navegador ainda necessários.
