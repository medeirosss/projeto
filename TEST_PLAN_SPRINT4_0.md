# Test Plan — Sprint 4.0

1. Subir banco/backend e confirmar migration `20260810_0025`.
2. Abrir **Tarefas > Repositórios** e confirmar MAGI, Atomic Red Team e Nuclei.
3. Confirmar MAGI como disponível e Nuclei como preparado.
4. Confirmar seis MAGI Security Checks.
5. Com Runner online, informar um host de homologação e clicar **Planejar**. Validar `ready=true`, runner, executor e remediation.
6. Executar RDP e SMB contra um host conhecido. Aguardar o Runner consumir o job.
7. Consultar `GET /api/repositories/executions` e confirmar evidence, finding_status e remediation.
8. Validar que porta fechada/filtrada retorna execução `success` com finding `not_detected`; isso diferencia falha do check de ausência da exposição.
9. Parar o Runner e confirmar que o Planner recusa nova execução com mensagem de Runner offline.
10. Revalidar uma técnica Atomic existente para garantir ausência de regressão.
