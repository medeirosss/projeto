from alembic import op
import sqlalchemy as sa


revision = "20260525_0008"
down_revision = "20260525_0007"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "alerts",
        sa.Column("recommended_actions", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade():
    op.drop_column("alerts", "recommended_actions")
