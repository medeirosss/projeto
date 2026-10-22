# MAGI 4.0 — versão consolidada

Esta versão consolida as correções 4.0.1 a 4.0.5 sob o número oficial **4.0**.

## Direção arquitetural
O fluxo principal passa a priorizar:
1. Inventário/Discovery
2. Exposure/CVE/configuração
3. MAGI Native Checks
4. Nuclei (próxima evolução planejada)
5. Evidence/Correlation
6. Remediation

## Atomic Red Team
O Atomic Red Team permanece no código e seu histórico continua consultável, porém está **congelado por padrão**.
Ele fica reservado para uma futura camada de **pós-ataque/pós-comprometimento** e não participa do fluxo operacional principal da 4.0.

A execução Atomic via API retorna HTTP 409 enquanto `ATOMIC_POST_ATTACK_ENABLED=false`.

## Conteúdo preservado
Todas as correções acumuladas de Repository Engine, Execution Planner, Evidence Engine, histórico unificado, target validation, credenciais e execução remota permanecem no código.
