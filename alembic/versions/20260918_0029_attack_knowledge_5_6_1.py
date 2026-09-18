from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision='20260918_0029'
down_revision='20260917_0028'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('knowledge_state',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('knowledge_schema',sa.Integer(),nullable=False,server_default='1'),
        sa.Column('knowledge_version',sa.String(40),nullable=False),
        sa.Column('source',sa.String(30),nullable=False,server_default='bundled'),
        sa.Column('full_snapshot',sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column('minimum_magi_version',sa.String(30),nullable=False,server_default='5.6.1'),
        sa.Column('applied_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')))
    op.create_table('attack_knowledge',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('attack_uuid',sa.String(40),nullable=False,unique=True),
        sa.Column('name',sa.String(200),nullable=False),
        sa.Column('description',sa.Text(),nullable=False),
        sa.Column('category',sa.String(40),nullable=False),
        sa.Column('impact',sa.String(20),nullable=False),
        sa.Column('status',sa.String(20),nullable=False,server_default='active'),
        sa.Column('source',sa.String(30),nullable=False,server_default='bundled'),
        sa.Column('knowledge_version',sa.String(40),nullable=False),
        sa.Column('metadata',postgresql.JSONB(),nullable=False,server_default=sa.text("'{}'::jsonb")),
        sa.Column('first_seen_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('deprecated_at',sa.DateTime(),nullable=True))
    op.create_index('idx_attack_knowledge_category','attack_knowledge',['category','impact','status'])
    op.create_table('attack_conditions',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('attack_id',sa.Integer(),sa.ForeignKey('attack_knowledge.id',ondelete='CASCADE'),nullable=False),
        sa.Column('condition_type',sa.String(40),nullable=False),
        sa.Column('operator',sa.String(20),nullable=False,server_default='eq'),
        sa.Column('value',postgresql.JSONB(),nullable=False),
        sa.Column('required',sa.Boolean(),nullable=False,server_default=sa.true()))
    op.create_index('idx_attack_conditions_attack','attack_conditions',['attack_id'])
    op.create_table('attack_cve_mappings',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('attack_id',sa.Integer(),sa.ForeignKey('attack_knowledge.id',ondelete='CASCADE'),nullable=False),
        sa.Column('cve_id',sa.String(32),nullable=False),
        sa.UniqueConstraint('attack_id','cve_id',name='uq_attack_cve'))
    op.create_table('attack_references',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('attack_id',sa.Integer(),sa.ForeignKey('attack_knowledge.id',ondelete='CASCADE'),nullable=False),
        sa.Column('reference_type',sa.String(30),nullable=False),
        sa.Column('reference_id',sa.String(200),nullable=False),
        sa.Column('url',sa.Text(),nullable=True))
    op.create_table('attack_technique_mappings',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('attack_id',sa.Integer(),sa.ForeignKey('attack_knowledge.id',ondelete='CASCADE'),nullable=False),
        sa.Column('technique_key',sa.String(80),nullable=False),
        sa.Column('provider',sa.String(30),nullable=False),
        sa.Column('executable',sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column('simulation_impact',sa.String(20),nullable=True),
        sa.UniqueConstraint('attack_id','technique_key',name='uq_attack_technique'))
    op.create_table('knowledge_sync_history',
        sa.Column('id',sa.BigInteger(),primary_key=True),
        sa.Column('from_version',sa.String(40),nullable=True),
        sa.Column('to_version',sa.String(40),nullable=False),
        sa.Column('source',sa.String(30),nullable=False),
        sa.Column('status',sa.String(20),nullable=False),
        sa.Column('inserted',sa.Integer(),nullable=False,server_default='0'),
        sa.Column('updated',sa.Integer(),nullable=False,server_default='0'),
        sa.Column('deprecated',sa.Integer(),nullable=False,server_default='0'),
        sa.Column('message',sa.Text(),nullable=True),
        sa.Column('applied_at',sa.DateTime(),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')))


def downgrade():
    for t in ('knowledge_sync_history','attack_technique_mappings','attack_references','attack_cve_mappings','attack_conditions','attack_knowledge','knowledge_state'):
        op.drop_table(t)
