"""
Exemplo de endpoint para Etapa 3D.

Ajuste os imports conforme a estrutura real do Magi.
A ideia é criar um runner_job atomic_validation com payload.mode = check_prereqs.
"""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/validations/atomic", tags=["Atomic Validations"])


@router.post("/executions/{execution_id}/check-prereqs")
def check_prereqs_execution(execution_id: int):
    """
    Fluxo esperado:
    1. Buscar atomic_execution_jobs.id = execution_id
    2. Validar status queued/pending_review/ready_for_prereq
    3. Buscar atomic_tests
    4. Criar runner_jobs com:
       job_type = atomic_validation
       payload.mode = check_prereqs
    5. Atualizar atomic_execution_jobs.status = prereq_queued
    """

    # Pseudocódigo intencional para patch seguro.
    # A implementação final deve usar os repositories reais do Magi.

    raise HTTPException(
        status_code=501,
        detail="Implementar usando atomic_repository/create_runner_job existentes."
    )