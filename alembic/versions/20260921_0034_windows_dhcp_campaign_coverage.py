"""5.7.3 Windows DHCP Provider and Campaign Coverage Intelligence."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision='20260921_0034'
down_revision='20260921_0033'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('attack_campaigns', sa.Column('dhcp_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('attack_campaigns', sa.Column('dhcp_server', sa.String(length=255)))
    op.add_column('attack_campaigns', sa.Column('dhcp_credential_id', sa.Integer()))
    op.create_table('attack_campaign_dhcp_runs',
        sa.Column('id',sa.Integer(),primary_key=True),sa.Column('execution_id',sa.Integer(),sa.ForeignKey('attack_campaign_executions.id',ondelete='CASCADE'),nullable=False),
        sa.Column('runner_job_id',sa.Integer()),sa.Column('dhcp_server',sa.String(255),nullable=False),sa.Column('status',sa.String(40),nullable=False,server_default='queued'),
        sa.Column('lease_count',sa.Integer(),nullable=False,server_default='0'),sa.Column('error',sa.Text()),sa.Column('created_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),sa.Column('finished_at',sa.DateTime()),
        sa.UniqueConstraint('execution_id',name='uq_campaign_dhcp_run_execution'))
    op.create_table('attack_campaign_dhcp_leases',
        sa.Column('id',sa.Integer(),primary_key=True),sa.Column('execution_id',sa.Integer(),sa.ForeignKey('attack_campaign_executions.id',ondelete='CASCADE'),nullable=False),
        sa.Column('ip_address',sa.String(64),nullable=False),sa.Column('hostname',sa.String(255)),sa.Column('client_id',sa.String(255)),sa.Column('address_state',sa.String(80)),
        sa.Column('scope_id',sa.String(64)),sa.Column('lease_expiry',sa.DateTime()),sa.Column('observed_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('execution_id','ip_address',name='uq_campaign_dhcp_lease_ip'))
    op.create_table('attack_campaign_coverage',
        sa.Column('id',sa.Integer(),primary_key=True),sa.Column('execution_id',sa.Integer(),sa.ForeignKey('attack_campaign_executions.id',ondelete='CASCADE'),nullable=False),
        sa.Column('ip_address',sa.String(64),nullable=False),sa.Column('hostname',sa.String(255)),sa.Column('target_id',sa.Integer(),sa.ForeignKey('targets.id',ondelete='SET NULL')),
        sa.Column('sources',postgresql.JSONB(),nullable=False,server_default=sa.text("'[]'::jsonb")),sa.Column('state',sa.String(40),nullable=False,server_default='KNOWN'),
        sa.Column('reached',sa.Boolean(),nullable=False,server_default=sa.text('false')),sa.Column('evaluated',sa.Boolean(),nullable=False,server_default=sa.text('false')),sa.Column('updated_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('execution_id','ip_address',name='uq_campaign_coverage_ip'))

def downgrade():
    op.drop_table('attack_campaign_coverage');op.drop_table('attack_campaign_dhcp_leases');op.drop_table('attack_campaign_dhcp_runs')
    op.drop_column('attack_campaigns','dhcp_credential_id');op.drop_column('attack_campaigns','dhcp_server');op.drop_column('attack_campaigns','dhcp_enabled')
