# MAGI 6.2.3 — Campaign UI & Evidence Refinement

Base: MAGI 6.2.2. Mudanças no frontend; backend e Runner preservados.

- Canvas estrutural preto (#000000), mantendo cards e acentos personalizados.
- Menu de ações da Campaign flutuante com posicionamento fixo, sem criar rolagem interna.
- Evidências em tabela com busca, filtro por status/protocolo, paginação e exportação CSV.
- Painel lateral de diagnóstico, resultado bruto, ciclo e Runner Job.
- IP destino obtido de campos explícitos de evidência/resultado ou mensagem identificada; quando ausente, 'Não registrado'. Não inferir IP por associação arbitrária.

Validação: node --check; integridade do ZIP. Testes integrados Docker e interface em navegador pendentes.
