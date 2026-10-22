from alembic import op
import sqlalchemy as sa


revision = "20260525_0005"
down_revision = "20260525_0004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("alerts", sa.Column("connectivity_status", sa.String(length=50), nullable=False, server_default="not_checked"))
    op.add_column("alerts", sa.Column("connectivity_message", sa.Text(), nullable=True))
    op.add_column("alerts", sa.Column("connectivity_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("alerts", "connectivity_at")
    op.drop_column("alerts", "connectivity_message")
    op.drop_column("alerts", "connectivity_status")
