from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.services.atomic_yaml_importer import import_atomic_yaml_tree

router = APIRouter(prefix="/api/atomic", tags=["atomic-import"])


class AtomicImportRequest(BaseModel):
    atomics_folder: str


@router.post("/import-yamls")
def import_yamls(payload: AtomicImportRequest, db: Session = Depends(get_db)):
    try:
        total = import_atomic_yaml_tree(db, payload.atomics_folder)
        return {"status": "ok", "imported_or_updated": total}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
