"""Zeek Native Telemetry

Revision ID: 0002_zeek_native_telemetry
Revises: 0001_initial_telemetry_schema
Create Date: 2026-08-30 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0002_zeek_native_telemetry'
down_revision: Union[str, None] = '0001_initial_telemetry_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update security_events table
    op.add_column('security_events', sa.Column('ml_classification_performed', sa.Boolean(), server_default='true', nullable=False))
    op.create_index('ix_security_events_ml_classification_performed', 'security_events', ['ml_classification_performed'])
    
    # Make ML columns nullable
    with op.batch_alter_table('security_events') as batch_op:
        batch_op.alter_column('predicted_family', existing_type=sa.String(64), nullable=True)
        batch_op.alter_column('class_confidence', existing_type=sa.Float(), nullable=True)
        batch_op.alter_column('normalized_anomaly_score', existing_type=sa.Float(), nullable=True)
        batch_op.alter_column('risk_score', existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column('severity', existing_type=sa.String(32), nullable=True)
        batch_op.alter_column('triage_status', existing_type=sa.String(32), nullable=True)
        batch_op.alter_column('class_probabilities', existing_type=sa.JSON(), nullable=True)
        batch_op.alter_column('feature_vector', existing_type=sa.JSON(), nullable=True)

    # 2. Update flow_provenance table
    op.add_column('flow_provenance', sa.Column('zeek_uid', sa.String(24), nullable=True))
    op.add_column('flow_provenance', sa.Column('conn_state', sa.String(8), nullable=True))
    op.add_column('flow_provenance', sa.Column('history', sa.String(64), nullable=True))
    op.add_column('flow_provenance', sa.Column('service', sa.String(32), nullable=True))
    op.add_column('flow_provenance', sa.Column('missed_bytes', sa.BigInteger(), nullable=True))
    op.add_column('flow_provenance', sa.Column('zeek_metadata', sa.JSON(), nullable=True))
    op.create_index('ix_flow_provenance_zeek_uid', 'flow_provenance', ['zeek_uid'])


def downgrade() -> None:
    op.drop_index('ix_flow_provenance_zeek_uid', table_name='flow_provenance')
    op.drop_column('flow_provenance', 'zeek_metadata')
    op.drop_column('flow_provenance', 'missed_bytes')
    op.drop_column('flow_provenance', 'service')
    op.drop_column('flow_provenance', 'history')
    op.drop_column('flow_provenance', 'conn_state')
    op.drop_column('flow_provenance', 'zeek_uid')

    with op.batch_alter_table('security_events') as batch_op:
        batch_op.alter_column('feature_vector', existing_type=sa.JSON(), nullable=False)
        batch_op.alter_column('class_probabilities', existing_type=sa.JSON(), nullable=False)
        batch_op.alter_column('triage_status', existing_type=sa.String(32), nullable=False)
        batch_op.alter_column('severity', existing_type=sa.String(32), nullable=False)
        batch_op.alter_column('risk_score', existing_type=sa.Integer(), nullable=False)
        batch_op.alter_column('normalized_anomaly_score', existing_type=sa.Float(), nullable=False)
        batch_op.alter_column('class_confidence', existing_type=sa.Float(), nullable=False)
        batch_op.alter_column('predicted_family', existing_type=sa.String(64), nullable=False)

    op.drop_index('ix_security_events_ml_classification_performed', table_name='security_events')
    op.drop_column('security_events', 'ml_classification_performed')
