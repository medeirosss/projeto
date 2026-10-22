"""service discovery engine

Revision ID: 20260807_0020
Revises: 20260806_0019
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260807_0020"
down_revision = "20260806_0019"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("discovery_scans", sa.Column("service_discovery_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    for name in ["service_jobs_total","service_jobs_completed","service_jobs_failed","services_found_count","new_services_count"]:
        op.add_column("discovery_runs", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))
    op.create_table(
        "asset_services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False, server_default="tcp"),
        sa.Column("service_name", sa.String(length=100)),
        sa.Column("friendly_name", sa.String(length=120)),
        sa.Column("category", sa.String(length=100)),
        sa.Column("product", sa.String(length=255)),
        sa.Column("version", sa.String(length=120)),
        sa.Column("extra_info", sa.String(length=255)),
        sa.Column("banner", sa.Text()),
        sa.Column("state", sa.String(length=30), nullable=False, server_default="open"),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("runner_id", sa.String(length=80)),
        sa.Column("last_discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="SET NULL")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("target_id","port","protocol",name="uq_asset_services_target_port_protocol"),
    )
    op.create_index("idx_asset_services_target", "asset_services", ["target_id","active","port"])
    op.create_table(
        "asset_service_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="SET NULL")),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False),
        sa.Column("state", sa.String(length=30)),
        sa.Column("service_name", sa.String(length=100)),
        sa.Column("friendly_name", sa.String(length=120)),
        sa.Column("category", sa.String(length=100)),
        sa.Column("product", sa.String(length=255)),
        sa.Column("version", sa.String(length=120)),
        sa.Column("is_new", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("observed_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "service_discovery_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("runner_job_id", sa.Integer(), sa.ForeignKey("runner_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("runner_id", sa.String(length=80)),
        sa.Column("target_ip", postgresql.INET(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
        sa.Column("service_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_service_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("raw_output", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
    )
    op.create_index("idx_service_discovery_jobs_run", "service_discovery_jobs", ["discovery_run_id","status"])


def downgrade():
    op.drop_index("idx_service_discovery_jobs_run", table_name="service_discovery_jobs")
    op.drop_table("service_discovery_jobs")
    op.drop_table("asset_service_observations")
    op.drop_index("idx_asset_services_target", table_name="asset_services")
    op.drop_table("asset_services")
    for name in reversed(["service_jobs_total","service_jobs_completed","service_jobs_failed","services_found_count","new_services_count"]):
        op.drop_column("discovery_runs", name)
    op.drop_column("discovery_scans", "service_discovery_enabled")
