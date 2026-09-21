"""5.7.2 Campaign Credential Sets and Network Intelligence foundation."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision='20260921_0033'
down_revision='20260920_0032'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('attack_campaigns', sa.Column('snmp_topology_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('attack_campaigns', sa.Column('windows_credential_ids', postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.execute("UPDATE attack_campaigns SET windows_credential_ids=jsonb_build_array(credential_id) WHERE credential_id IS NOT NULL AND windows_credential_ids='[]'::jsonb")
    op.add_column('attack_campaign_paths', sa.Column('credential_id', sa.Integer(), nullable=False, server_default='0'))
    op.execute("UPDATE attack_campaign_paths SET credential_id=COALESCE(NULLIF(evidence->>'credential_id','')::int,0) WHERE evidence ? 'credential_id'")
    op.drop_constraint('uq_attack_campaign_path_vector','attack_campaign_paths',type_='unique')
    op.create_unique_constraint('uq_attack_campaign_path_vector_credential','attack_campaign_paths',['execution_id','origin','target','protocol','credential_id'])

def downgrade():
    op.drop_constraint('uq_attack_campaign_path_vector_credential','attack_campaign_paths',type_='unique')
    op.create_unique_constraint('uq_attack_campaign_path_vector','attack_campaign_paths',['execution_id','origin','target','protocol'])
    op.drop_column('attack_campaign_paths','credential_id')
    op.drop_column('attack_campaigns','windows_credential_ids')
    op.drop_column('attack_campaigns','snmp_topology_enabled')
