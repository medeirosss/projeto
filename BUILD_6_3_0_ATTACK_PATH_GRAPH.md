# MAGI 6.3.0 — Attack Path Graph

Base: projeto-hml.rar enviado pelo usuário em 03/11/2026.

## Mudanças
- `frontend/attack-path-graph.js`: componente de visualização reutilizável (`window.MAGIAttackPath.mount(root, payload, {compact:false})`).
- `frontend/attack-path-graph.css`: estilo isolado, respeita tokens `--magi-*`.
- `frontend/attack-simulator.js`: aba Attack Path da Campaign passa a renderizar o grafo; nova visualização selecionável na página Attack Path.
- `frontend/attack-simulator.html`: imports do componente, seletor de Campaign e histórico técnico preservado.

## Sem alterações
Backend, Runner, banco de dados, migrations e agendamento das Campaigns permanecem inalterados.

## Restrições importantes
- As conexões exibidas provêm exclusivamente de `GET /api/attack-simulator/campaigns/{uuid}/attack-path`.
- `ACCESS` é exibido como acesso confirmado; SNMP é topologia, nunca movimento lateral.
- A UI não atribui Windows/Linux por suposição. Com o payload atual, os nós sem metadados de SO ficam genéricos. A identificação confiável por SO exige enriquecimento do endpoint em uma revisão posterior.
- A expansão/recolhimento mostra apenas arestas que já existem no payload. Não cria saltos.
- O grafo é SVG com layout em camadas, não usa biblioteca de terceiros. A visualização pode ficar densa em Campaigns grandes; layout de alto volume é melhoria futura.
- Não foi realizado teste integrado em Docker ou navegador com dados reais.

## Teste manual
1. Publicar a imagem gerada pelo GitHub Actions a partir desta base.
2. Abrir Attack Simulation > Campaign > Detalhes > Attack Path; confirmar que as 4 barreiras anteriores aparecem como arestas vermelhas tracejadas, sem acesso confirmado inventado.
3. Selecionar uma conexão: conferir Runner Job, protocolo, ciclo, motivo e evidência.
4. Filtrar SMB/WinRM e confirmar que o número de arestas muda corretamente.
5. Expandir/recolher um host com conexões de saída; confirmar que os demais nós permanecem estáveis.
6. Abrir Attack Simulation > Attack Path, selecionar Campaign e visualizar o mesmo grafo.
7. Testar zoom, navegação por teclado e viewport menor que 900px.
8. Confirmar que Campaign, Runner e demais páginas permanecem funcionais.
