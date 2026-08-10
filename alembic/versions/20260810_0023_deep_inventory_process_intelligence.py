"""deep inventory and process intelligence

Revision ID: 20260810_0023
Revises: 20260810_0022
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260810_0023"
down_revision = "20260810_0022"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("discovery_scans", sa.Column("deep_inventory_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("discovery_scans", sa.Column("deep_inventory_interval_minutes", sa.Integer(), nullable=False, server_default="30"))
    for name in ["deep_jobs_total","deep_jobs_completed","deep_jobs_failed","deep_jobs_success","hardware_changes_count","process_findings_count"]:
        op.add_column("discovery_runs", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))
    op.create_table(
        "asset_inventory_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("hostname", sa.String(length=255)),
        sa.Column("os_name", sa.String(length=255)),
        sa.Column("os_version", sa.String(length=100)),
        sa.Column("os_build", sa.String(length=100)),
        sa.Column("domain_name", sa.String(length=255)),
        sa.Column("manufacturer", sa.String(length=255)),
        sa.Column("model", sa.String(length=255)),
        sa.Column("serial_number", sa.String(length=255)),
        sa.Column("cpu_model", sa.String(length=255)),
        sa.Column("cpu_cores", sa.Integer()),
        sa.Column("cpu_logical", sa.Integer()),
        sa.Column("memory_bytes", sa.BigInteger()),
        sa.Column("disks", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("uptime_seconds", sa.BigInteger()),
        sa.Column("runner_id", sa.String(length=100)),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="SET NULL")),
        sa.Column("collected_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "asset_hardware_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("component", sa.String(length=80), nullable=False),
        sa.Column("field_name", sa.String(length=120), nullable=False),
        sa.Column("old_value", sa.Text()),
        sa.Column("new_value", sa.Text()),
        sa.Column("runner_id", sa.String(length=100)),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="SET NULL")),
        sa.Column("detected_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_asset_hardware_changes_target", "asset_hardware_changes", ["target_id","detected_at"])
    op.create_table(
        "process_knowledge_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("process_name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False, server_default="non_authorized"),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("process_name", name="uq_process_knowledge_process_name"),
    )
    op.create_table(
        "asset_process_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("process_knowledge_rules.id", ondelete="SET NULL")),
        sa.Column("process_name", sa.String(length=255), nullable=False),
        sa.Column("process_path", sa.Text()),
        sa.Column("pid", sa.Integer()),
        sa.Column("sha256", sa.String(length=64)),
        sa.Column("publisher", sa.String(length=255)),
        sa.Column("signed", sa.Boolean()),
        sa.Column("category", sa.String(length=50)),
        sa.Column("severity", sa.String(length=20)),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("currently_detected", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("target_id","rule_id", name="uq_asset_process_finding_target_rule"),
    )
    op.create_index("idx_asset_process_findings_target", "asset_process_findings", ["target_id","currently_detected"])
    op.create_table(
        "deep_inventory_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="SET NULL")),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("discovery_scans.id", ondelete="SET NULL")),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("stored_credentials.id", ondelete="SET NULL")),
        sa.Column("runner_job_id", sa.Integer(), sa.ForeignKey("runner_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("runner_id", sa.String(length=100)),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
        sa.Column("hardware_changes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("process_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
    )
    op.create_index("idx_deep_inventory_jobs_target", "deep_inventory_jobs", ["target_id","status"])


def downgrade():
    op.drop_index("idx_deep_inventory_jobs_target", table_name="deep_inventory_jobs")
    op.drop_table("deep_inventory_jobs")
    op.drop_index("idx_asset_process_findings_target", table_name="asset_process_findings")
    op.drop_table("asset_process_findings")
    op.drop_table("process_knowledge_rules")
    op.drop_index("idx_asset_hardware_changes_target", table_name="asset_hardware_changes")
    op.drop_table("asset_hardware_changes")
    op.drop_table("asset_inventory_snapshot")
    for name in reversed(["deep_jobs_total","deep_jobs_completed","deep_jobs_failed","deep_jobs_success","hardware_changes_count","process_findings_count"]):
        op.drop_column("discovery_runs", name)
    op.drop_column("discovery_scans", "deep_inventory_interval_minutes")
    op.drop_column("discovery_scans", "deep_inventory_enabled")
