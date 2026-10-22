from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260525_0003"
down_revision = "20260525_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "validation_jobs",
        sa.Column("runner_job_id", sa.Integer(), nullable=True),
    )

    op.create_foreign_key(
        "validation_jobs_runner_job_id_fkey",
        "validation_jobs",
        "runner_jobs",
        ["runner_job_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "validation_jobs_runner_job_id_fkey",
        "validation_jobs",
        type_="foreignkey",
    )
    op.drop_column("validation_jobs", "runner_job_id")
