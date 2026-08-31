"""runner v2 tables

Revision ID: 002_runner_v2
Revises: 
Create Date: 2026-07-06
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_runner_v2"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runners",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("runner_uuid", sa.String(length=64), nullable=False, unique=True),
        sa.Column("runner_name", sa.String(length=255), nullable=False),
        sa.Column("runner_group", sa.String(length=120), nullable=False, server_default="default"),
        sa.Column("runner_secret_hash", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="registered"),
        sa.Column("version", sa.String(length=80), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("os_name", sa.String(length=120), nullable=True),
        sa.Column("ip_address", sa.String(length=80), nullable=True),
        sa.Column("host_info", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("last_heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_runners_status", "runners", ["status"])
    op.create_index("ix_runners_group", "runners", ["runner_group"])
    op.create_index("ix_runners_last_heartbeat", "runners", ["last_heartbeat_at"])

    op.create_table(
        "runner_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_uuid", sa.String(length=64), nullable=False, unique=True),
        sa.Column("runner_uuid", sa.String(length=64), sa.ForeignKey("runners.runner_uuid", ondelete="SET NULL"), nullable=True),
        sa.Column("runner_group", sa.String(length=120), nullable=False, server_default="default"),
        sa.Column("job_type", sa.String(length=60), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_runner_jobs_queue", "runner_jobs", ["status", "runner_uuid", "runner_group", "priority", "created_at"])
    op.create_index("ix_runner_jobs_runner", "runner_jobs", ["runner_uuid"])
    op.create_index("ix_runner_jobs_status", "runner_jobs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_runner_jobs_status", table_name="runner_jobs")
    op.drop_index("ix_runner_jobs_runner", table_name="runner_jobs")
    op.drop_index("ix_runner_jobs_queue", table_name="runner_jobs")
    op.drop_table("runner_jobs")
    op.drop_index("ix_runners_last_heartbeat", table_name="runners")
    op.drop_index("ix_runners_group", table_name="runners")
    op.drop_index("ix_runners_status", table_name="runners")
    op.drop_table("runners")
