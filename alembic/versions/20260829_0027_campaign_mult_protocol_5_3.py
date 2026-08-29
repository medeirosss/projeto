"""MAGI 5.3 multi-protocol campaign fields.

Revision ID: 20260829_0027
Revises: 20260826_0026
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision='20260829_0027'
down_revision='20260826_0026'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('attack_campaigns',sa.Column('ssh_credential_id',sa.Integer(),nullable=True))
    op.add_column('attack_campaigns',sa.Column('snmp_credential_id',sa.Integer(),nullable=True))
    op.add_column('attack_campaigns',sa.Column('enabled_vectors',postgresql.JSONB(astext_type=sa.Text()),nullable=False,server_default=sa.text("'[\"winrm\",\"smb\",\"ssh\",\"snmp_v2c\"]'::jsonb")))
    op.add_column('attack_campaigns',sa.Column('create_benign_evidence',sa.Boolean(),nullable=False,server_default=sa.text('false')))
    op.add_column('attack_campaign_paths',sa.Column('protocol',sa.String(length=30),nullable=False,server_default='winrm'))
    op.add_column('attack_campaign_paths',sa.Column('relation_type',sa.String(length=30),nullable=False,server_default='access'))
    op.drop_constraint('attack_campaign_paths_execution_id_origin_target_key','attack_campaign_paths',type_='unique')
    op.create_unique_constraint('uq_attack_campaign_path_vector','attack_campaign_paths',['execution_id','origin','target','protocol'])

def downgrade():
    op.drop_constraint('uq_attack_campaign_path_vector','attack_campaign_paths',type_='unique')
    op.create_unique_constraint('attack_campaign_paths_execution_id_origin_target_key','attack_campaign_paths',['execution_id','origin','target'])
    op.drop_column('attack_campaign_paths','relation_type'); op.drop_column('attack_campaign_paths','protocol')
    op.drop_column('attack_campaigns','create_benign_evidence'); op.drop_column('attack_campaigns','enabled_vectors')
    op.drop_column('attack_campaigns','snmp_credential_id'); op.drop_column('attack_campaigns','ssh_credential_id')
