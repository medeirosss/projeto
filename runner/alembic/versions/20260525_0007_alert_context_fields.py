from alembic import op
import sqlalchemy as sa


revision = "20260525_0007"
down_revision = "20260525_0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("alerts", sa.Column("context_summary", sa.Text(), nullable=False, server_default=""))
    op.add_column("alerts", sa.Column("context_category", sa.String(length=80), nullable=False, server_default="generic"))


def downgrade():
    op.drop_column("alerts", "context_category")
    op.drop_column("alerts", "context_summary")
