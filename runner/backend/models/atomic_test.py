from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, func
from backend.database import Base


class AtomicTest(Base):
    __tablename__ = "atomic_tests"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(50), nullable=False, index=True)

    # Número real do teste dentro do YAML do Atomic Red Team.
    # Exemplo: T1087.001-8 => atomic_test_number = 8.
    atomic_test_number = Column(Integer, nullable=False)

    auto_generated_guid = Column(String(80), nullable=True)
    display_name = Column(String(255), nullable=True)
    atomic_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    supported_platforms = Column(Text, nullable=True)  # JSON string: ["windows"]
    executor_name = Column(String(80), nullable=True)
    executor_elevation_required = Column(Boolean, nullable=False, default=False)
    has_dependencies = Column(Boolean, nullable=False, default=False)
    dependency_count = Column(Integer, nullable=False, default=0)

    # Produto não bloqueia por padrão. Quem bloqueia/libera é o admin.
    approved = Column(Boolean, nullable=False, default=True)
    lab_enabled = Column(Boolean, nullable=False, default=True)

    source_yaml_path = Column(Text, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
