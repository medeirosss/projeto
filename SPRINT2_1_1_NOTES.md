# Sprint 2.1.1 — DNS Enrichment

- Configuração global de DNS em Configurações > Discovery > DNS.
- DNS primário/secundário, sufixo, timeout e fallback do sistema.
- Configuração enviada pelo backend ao Runner em cada job de discovery.
- Consulta PTR executada dentro da rede pelo Runner.
- Persistência de `dns_name` e `hostname_source`.
- Ausência de PTR não interrompe o scan.
- Online/offline e detecção de SO permanecem fora deste escopo.
