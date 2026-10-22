from pydantic import BaseModel, Field


class AtomicLabExecuteRequest(BaseModel):
    runner_id: str = Field(..., min_length=1)
    technique_id: str = Field(..., min_length=1)
    atomic_test_number: int = Field(..., ge=1)


class AtomicLabExecuteResponse(BaseModel):
    status: str
    message: str
    technique_id: str
    atomic_test_number: int
    runner_id: str
