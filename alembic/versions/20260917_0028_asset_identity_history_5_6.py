from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision='20260917_0028'
down_revision='20260829_0027'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('targets',sa.Column('identity_status',sa.String(30),nullable=False,server_default='LEGACY'))
    op.add_column('targets',sa.Column('identity_confidence',sa.Integer(),nullable=False,server_default='0'))
    op.add_column('targets',sa.Column('identity_reason',sa.String(100),nullable=True))
    op.add_column('targets',sa.Column('identity_evaluated_at',sa.DateTime(),nullable=True))
    op.create_table('asset_identifiers',
        sa.Column('id',sa.Integer(),primary_key=True),sa.Column('target_id',sa.Integer(),sa.ForeignKey('targets.id',ondelete='CASCADE'),nullable=False),
        sa.Column('identifier_type',sa.String(40),nullable=False),sa.Column('identifier_value',sa.String(512),nullable=False),sa.Column('source',sa.String(60),nullable=False,server_default='discovery'),
        sa.Column('confidence',sa.Integer(),nullable=False,server_default='50'),sa.Column('first_seen_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('last_seen_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),sa.Column('is_current',sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.UniqueConstraint('target_id','identifier_type','identifier_value',name='uq_asset_identifier'))
    op.create_index('idx_asset_identifiers_lookup','asset_identifiers',['identifier_type','identifier_value'])
    op.create_table('asset_identity_events',
        sa.Column('id',sa.BigInteger(),primary_key=True),sa.Column('target_id',sa.Integer(),sa.ForeignKey('targets.id',ondelete='CASCADE'),nullable=False),
        sa.Column('match_status',sa.String(30),nullable=False),sa.Column('confidence',sa.Integer(),nullable=False,server_default='0'),sa.Column('reason',sa.String(100),nullable=False),
        sa.Column('evidence',postgresql.JSONB(),nullable=False,server_default=sa.text("'{}'::jsonb")),sa.Column('observed_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')))
    op.create_index('idx_asset_identity_events_target','asset_identity_events',['target_id','observed_at'])
    op.add_column('attack_campaign_assets',sa.Column('target_id',sa.Integer(),sa.ForeignKey('targets.id',ondelete='SET NULL'),nullable=True))
    op.create_index('idx_attack_campaign_assets_target','attack_campaign_assets',['target_id'])
    op.add_column('validation_task_executions',sa.Column('target_id',sa.Integer(),sa.ForeignKey('targets.id',ondelete='SET NULL'),nullable=True))
    op.create_index('idx_validation_executions_target','validation_task_executions',['target_id'])
    op.create_table('exposure_finding_occurrences',
        sa.Column('id',sa.BigInteger(),primary_key=True),sa.Column('finding_id',sa.Integer(),sa.ForeignKey('exposure_findings.id',ondelete='CASCADE'),nullable=False),
        sa.Column('opened_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),sa.Column('last_seen_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('resolved_at',sa.DateTime(),nullable=True),sa.Column('status',sa.String(20),nullable=False,server_default='open'))
    op.create_index('idx_exposure_occurrence_finding','exposure_finding_occurrences',['finding_id','opened_at'])
    # Backfill stable identifiers without changing legacy target identity.
    op.execute("""INSERT INTO asset_identifiers(target_id,identifier_type,identifier_value,source,confidence,first_seen_at,last_seen_at,is_current)
        SELECT id,'mac',lower(mac_normalized),'migration',95,first_seen_at,last_seen_at,TRUE FROM targets WHERE mac_normalized IS NOT NULL AND mac_normalized<>'' ON CONFLICT DO NOTHING""")
    op.execute("""INSERT INTO asset_identifiers(target_id,identifier_type,identifier_value,source,confidence,first_seen_at,last_seen_at,is_current)
        SELECT id,'hostname',lower(hostname_normalized),'migration',80,first_seen_at,last_seen_at,TRUE FROM targets WHERE hostname_normalized IS NOT NULL AND hostname_normalized<>'' ON CONFLICT DO NOTHING""")
    op.execute("""INSERT INTO asset_identifiers(target_id,identifier_type,identifier_value,source,confidence,first_seen_at,last_seen_at,is_current)
        SELECT id,'fqdn',lower(dns_name),'migration',85,first_seen_at,last_seen_at,TRUE FROM targets WHERE dns_name IS NOT NULL AND dns_name<>'' ON CONFLICT DO NOTHING""")
    op.execute("""INSERT INTO exposure_finding_occurrences(finding_id,opened_at,last_seen_at,resolved_at,status)
        SELECT id,first_seen_at,last_seen_at,resolved_at,CASE WHEN status='resolved' THEN 'resolved' ELSE 'open' END FROM exposure_findings""")


def downgrade():
    op.drop_table('exposure_finding_occurrences')
    op.drop_index('idx_validation_executions_target',table_name='validation_task_executions'); op.drop_column('validation_task_executions','target_id')
    op.drop_index('idx_attack_campaign_assets_target',table_name='attack_campaign_assets'); op.drop_column('attack_campaign_assets','target_id')
    op.drop_table('asset_identity_events'); op.drop_table('asset_identifiers')
    for c in ('identity_evaluated_at','identity_reason','identity_confidence','identity_status'): op.drop_column('targets',c)
