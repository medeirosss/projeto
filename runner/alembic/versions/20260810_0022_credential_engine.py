"""credential engine

Revision ID: 20260810_0022
Revises: 20260807_0021
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260810_0022"
down_revision = "20260807_0021"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("discovery_scans", sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="SET NULL")))
    for name in ["credential_jobs_total","credential_jobs_completed","credential_jobs_failed","credential_jobs_success"]:
        op.add_column("discovery_runs", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))
    op.create_table(
        "credential_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="CASCADE")),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("runner_job_id", sa.Integer(), sa.ForeignKey("runner_jobs.id", ondelete="CASCADE"), unique=True),
        sa.Column("runner_id", sa.String(length=100)),
        sa.Column("target_ip", postgresql.INET(), nullable=False),
        sa.Column("protocol", sa.String(length=30)),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
        sa.Column("attempts_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hostname_result", sa.String(length=255)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
    )
    op.create_index("idx_credential_attempts_run", "credential_attempts", ["discovery_run_id","status"])
    op.create_table(
        "asset_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("protocol", sa.String(length=30), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("hostname_result", sa.String(length=255)),
        sa.Column("runner_id", sa.String(length=100)),
        sa.UniqueConstraint("target_id","credential_id","protocol",name="uq_asset_credentials_target_credential_protocol"),
    )


def downgrade():
    op.drop_table("asset_credentials")
    op.drop_index("idx_credential_attempts_run", table_name="credential_attempts")
    op.drop_table("credential_attempts")
    for name in reversed(["credential_jobs_total","credential_jobs_completed","credential_jobs_failed","credential_jobs_success"]):
        op.drop_column("discovery_runs", name)
    op.drop_column("discovery_scans", "credential_id")
