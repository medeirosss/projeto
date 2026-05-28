from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260527_0009"
down_revision = "20260525_0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "atomic_import_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="success"),
        sa.Column("techniques_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tests_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "atomic_techniques",
        sa.Column("technique_id", sa.String(length=40), primary_key=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("attack_tactic", sa.Text(), nullable=True),
        sa.Column("atomic_tests_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("platforms", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("executors", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("source_file", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "atomic_tests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("technique_id", sa.String(length=40), sa.ForeignKey("atomic_techniques.technique_id", ondelete="CASCADE"), nullable=False),
        sa.Column("atomic_name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("supported_platforms", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("executor_name", sa.String(length=80), nullable=True),
        sa.Column("executor_elevation_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("has_dependencies", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("dependency_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input_arguments", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("risk_flags", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("risk_level", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("approved_for_lab", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("source_file", sa.Text(), nullable=True),
        sa.Column("raw_yaml", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_atomic_tests_technique_id", "atomic_tests", ["technique_id"])
    op.create_index("ix_atomic_tests_executor_name", "atomic_tests", ["executor_name"])
    op.create_index("ix_atomic_tests_risk_level", "atomic_tests", ["risk_level"])


def downgrade():
    op.drop_index("ix_atomic_tests_risk_level", table_name="atomic_tests")
    op.drop_index("ix_atomic_tests_executor_name", table_name="atomic_tests")
    op.drop_index("ix_atomic_tests_technique_id", table_name="atomic_tests")
    op.drop_table("atomic_tests")
    op.drop_table("atomic_techniques")
    op.drop_table("atomic_import_runs")
