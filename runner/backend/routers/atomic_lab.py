import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.atomic_test import AtomicTest
from backend.schemas.atomic_lab import AtomicLabExecuteRequest, AtomicLabExecuteResponse

router = APIRouter(prefix="/api/validations/lab", tags=["validations-lab"])


@router.post("/execute", response_model=AtomicLabExecuteResponse)
def execute_atomic_lab(payload: AtomicLabExecuteRequest, db: Session = Depends(get_db)):
    """
    Executa usando technique_id + atomic_test_number real.
    Não usa o id interno da tabela como TestNumbers.
    """
    test = (
        db.query(AtomicTest)
        .filter(
            AtomicTest.technique_id == payload.technique_id,
            AtomicTest.atomic_test_number == payload.atomic_test_number,
        )
        .first()
    )

    if not test:
        raise HTTPException(
            status_code=404,
            detail="Teste Atomic não encontrado para technique_id + atomic_test_number.",
        )

    if not test.approved or not test.lab_enabled:
        raise HTTPException(
            status_code=403,
            detail="Teste não aprovado/habilitado pelo administrador.",
        )

    # Aqui você deve chamar o serviço/fila real do runner já existente no Magi.
    # O ponto principal é enviar atomic_test_number, não test.id.
    command_payload = {
        "runner_id": payload.runner_id,
        "technique_id": payload.technique_id,
        "atomic_test_number": payload.atomic_test_number,
        "atomic_name": test.atomic_name,
        "executor_name": test.executor_name,
        "supported_platforms": json.loads(test.supported_platforms or "[]"),
    }

    # TODO: substituir pelo método real do Magi, por exemplo:
    # runner_queue.enqueue_atomic_test(command_payload)
    print("MAGI_ATOMIC_EXECUTE_PAYLOAD", command_payload)

    return AtomicLabExecuteResponse(
        status="queued",
        message="Execução enviada para o runner usando atomic_test_number real.",
        technique_id=payload.technique_id,
        atomic_test_number=payload.atomic_test_number,
        runner_id=payload.runner_id,
    )
