from fastapi import APIRouter

router = APIRouter(prefix="/api/validations/atomic")

@router.post("/tests/{test_id}/approve")
async def approve_test(test_id: int):
    return {"status": "approved", "test_id": test_id}

@router.post("/tests/{test_id}/risk")
async def update_risk(test_id: int, risk_level: str):
    return {"status": "updated", "risk_level": risk_level}

@router.post("/tests/{test_id}/flags")
async def update_flags(test_id: int):
    return {"status": "updated"}