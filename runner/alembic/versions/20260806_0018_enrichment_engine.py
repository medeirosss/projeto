"""enrichment engine fingerprint fields

Revision ID: 20260806_0018
Revises: 20260802_0017
"""
from alembic import op
import sqlalchemy as sa

revision = "20260806_0018"
down_revision = "20260802_0017"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("targets", sa.Column("fingerprint_confidence", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("targets", sa.Column("fingerprint_rule", sa.String(length=100), nullable=True))
    op.add_column("targets", sa.Column("fingerprint_reasons", sa.Text(), nullable=True))
    op.add_column("targets", sa.Column("fingerprinted_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("targets", "fingerprinted_at")
    op.drop_column("targets", "fingerprint_reasons")
    op.drop_column("targets", "fingerprint_rule")
    op.drop_column("targets", "fingerprint_confidence")
