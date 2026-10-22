"""enrichment visibility, asset compliance and inventory cleanup

Revision ID: 20260806_0019
Revises: 20260806_0018
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260806_0019"
down_revision = "20260806_0018"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("targets", sa.Column("active_in_inventory", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("targets", sa.Column("retired_at", sa.DateTime(), nullable=True))
    op.add_column("targets", sa.Column("retired_reason", sa.String(length=80), nullable=True))
    op.add_column("targets", sa.Column("consecutive_misses", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("targets", sa.Column("confidence_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("targets", sa.Column("last_enrichment_status", sa.String(length=30), nullable=True))
    op.add_column("discovery_scan_targets", sa.Column("consecutive_misses", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("discovery_scans", sa.Column("cleanup_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("discovery_scans", sa.Column("cleanup_missed_scans", sa.Integer(), nullable=False, server_default="10"))
    for name in ["new_count","updated_count","dns_success_count","dns_failed_count","fingerprint_success_count","fingerprint_failed_count","classified_count","unknown_count"]:
        op.add_column("discovery_runs", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))
    op.add_column("discovery_runs", sa.Column("pipeline_status", sa.String(length=30), nullable=True))
    op.create_table(
        "asset_compliance_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_type", sa.String(length=30), nullable=False, unique=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("starts_with", sa.String(length=80)),
        sa.Column("contains_text", sa.String(length=80)),
        sa.Column("ends_with", sa.String(length=80)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "enrichment_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discovery_run_id", sa.Integer(), sa.ForeignKey("discovery_runs.id", ondelete="SET NULL")),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("is_new", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("stages", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("classification", sa.String(length=50)),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_enrichment_events_run", "enrichment_events", ["discovery_run_id", "created_at"])


def downgrade():
    op.drop_index("idx_enrichment_events_run", table_name="enrichment_events")
    op.drop_table("enrichment_events")
    op.drop_table("asset_compliance_rules")
    op.drop_column("discovery_runs", "pipeline_status")
    for name in reversed(["new_count","updated_count","dns_success_count","dns_failed_count","fingerprint_success_count","fingerprint_failed_count","classified_count","unknown_count"]):
        op.drop_column("discovery_runs", name)
    op.drop_column("discovery_scans", "cleanup_missed_scans")
    op.drop_column("discovery_scans", "cleanup_enabled")
    op.drop_column("discovery_scan_targets", "consecutive_misses")
    op.drop_column("targets", "last_enrichment_status")
    op.drop_column("targets", "confidence_details")
    op.drop_column("targets", "consecutive_misses")
    op.drop_column("targets", "retired_reason")
    op.drop_column("targets", "retired_at")
    op.drop_column("targets", "active_in_inventory")
