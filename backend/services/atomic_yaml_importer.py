import json
from pathlib import Path
from typing import Iterable

import yaml
from sqlalchemy.orm import Session

from backend.models.atomic_test import AtomicTest


def _as_bool(value) -> bool:
    return bool(value) if value is not None else False


def import_atomic_yaml_file(db: Session, yaml_file: Path) -> int:
    """
    Importa SOMENTE metadados do YAML para o banco.
    Não salva comando, cleanup_command nem conteúdo completo do YAML.

    Importante:
    - atomic_test_number é a posição real do teste no YAML, começando em 1.
    - Isso corrige o bug onde o Magi usava o id interno da tabela como TestNumbers.
    """
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    technique_id = data.get("attack_technique")
    display_name = data.get("display_name")
    atomic_tests = data.get("atomic_tests") or []

    if not technique_id:
        return 0

    imported = 0

    for index, item in enumerate(atomic_tests, start=1):
        executor = item.get("executor") or {}
        dependencies = item.get("dependencies") or []
        platforms = item.get("supported_platforms") or []

        existing = (
            db.query(AtomicTest)
            .filter(
                AtomicTest.technique_id == technique_id,
                AtomicTest.atomic_test_number == index,
            )
            .first()
        )

        values = {
            "technique_id": technique_id,
            "atomic_test_number": index,
            "auto_generated_guid": item.get("auto_generated_guid"),
            "display_name": display_name,
            "atomic_name": item.get("name") or f"{technique_id}-{index}",
            "description": item.get("description"),
            "supported_platforms": json.dumps(platforms),
            "executor_name": executor.get("name"),
            "executor_elevation_required": _as_bool(executor.get("elevation_required")),
            "has_dependencies": bool(dependencies),
            "dependency_count": len(dependencies),
            "approved": True,
            "lab_enabled": True,
            "source_yaml_path": str(yaml_file),
        }

        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
        else:
            db.add(AtomicTest(**values))

        imported += 1

    db.commit()
    return imported


def import_atomic_yaml_tree(db: Session, atomics_folder: str) -> int:
    """
    Espera o caminho da pasta atomics, exemplo:
    C:\\Program Files\\Magi Runner\\atomic-red-team\\atomics
    """
    root = Path(atomics_folder)
    total = 0

    for yaml_file in root.glob("T*/T*.yaml"):
        total += import_atomic_yaml_file(db, yaml_file)

    return total
