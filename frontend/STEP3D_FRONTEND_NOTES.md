# Frontend - Etapa 3D

Adicionar novo botão no card/histórico de execução:

- Check Prereqs

Fluxo:
1. Preparar execução
2. Enviar ao Runner / Dry Run
3. Check Prereqs
4. Futuro: Executar em LAB

Status sugeridos:
- prereq_queued
- prereq_running
- prereq_ready
- prereq_needs_review
- prereq_blocked

Exibir no resultado:
- readiness_status
- blockers
- warnings
- dependency_count
- requires_admin
- executor_supported