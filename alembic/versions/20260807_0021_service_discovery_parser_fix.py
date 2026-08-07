"""service discovery parser fix

Revision ID: 20260807_0021
Revises: 20260807_0020
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260807_0021"
down_revision = "20260807_0020"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("asset_services", sa.Column("os_type", sa.String(length=80)))
    op.add_column("asset_services", sa.Column("cpe", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("asset_services", sa.Column("service_fingerprint", sa.Text()))
    op.add_column("asset_services", sa.Column("tunnel", sa.String(length=30)))
    op.add_column("asset_services", sa.Column("detection_method", sa.String(length=30)))
    op.add_column("asset_services", sa.Column("detection_confidence", sa.Integer()))

def downgrade():
    op.drop_column("asset_services", "detection_confidence")
    op.drop_column("asset_services", "detection_method")
    op.drop_column("asset_services", "tunnel")
    op.drop_column("asset_services", "service_fingerprint")
    op.drop_column("asset_services", "cpe")
    op.drop_column("asset_services", "os_type")
