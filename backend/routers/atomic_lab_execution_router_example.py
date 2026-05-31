from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.atomic_lab_execution_service import create_atomic_lab_execution_service


router = APIRouter(prefix="/api/validations/atomic", tags=["Atomic Validations"])


class AtomicLabExecuteRequest(BaseModel):
    runner_id: str


@router.post("/tests/{atomic_test_id}/execute-lab")
def execute_atomic_lab(atomic_test_id: int, body: AtomicLabExecuteRequest):
    try:
        # TODO: substituir por usuário autenticado real.
        current_user = {
            "username": "ui-admin",
            "role": "admin",
        }

        return create_atomic_lab_execution_service(
            atomic_test_id=atomic_test_id,
            runner_id=body.runner_id,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))