"""exposure engine

Revision ID: 20260810_0024
Revises: 20260810_0023
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260810_0024"
down_revision = "20260810_0023"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "exposure_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_uuid", sa.String(length=40), nullable=False, unique=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("source_type", sa.String(length=30), nullable=False),
        sa.Column("source_key", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("ignored_at", sa.DateTime()),
        sa.Column("ignored_reason", sa.Text()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("target_id", "source_type", "source_key", name="uq_exposure_target_source"),
    )
    op.create_index("idx_exposure_findings_status", "exposure_findings", ["status", "severity"])
    op.create_index("idx_exposure_findings_target", "exposure_findings", ["target_id", "status"])


def downgrade():
    op.drop_index("idx_exposure_findings_target", table_name="exposure_findings")
    op.drop_index("idx_exposure_findings_status", table_name="exposure_findings")
    op.drop_table("exposure_findings")
