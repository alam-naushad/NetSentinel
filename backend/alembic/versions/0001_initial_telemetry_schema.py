"""Initial Security Telemetry & Incident Management Schema.

Revision ID: 0001_initial_telemetry_schema
Revises: None
Create Date: 2026-08-30 20:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0001_initial_telemetry_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. analysis_jobs table
    op.create_table(
        'analysis_jobs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('source_type', sa.String(32), nullable=False, server_default='PCAP_BATCH'),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('file_sha256', sa.String(64), nullable=True),
        sa.Column('total_flows_extracted', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_flows_analyzed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('anomalies_flagged', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('processing_time_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('status', sa.String(32), nullable=False, server_default='COMPLETED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_analysis_jobs_source_type', 'analysis_jobs', ['source_type'])
    op.create_index('ix_analysis_jobs_file_sha256', 'analysis_jobs', ['file_sha256'])
    op.create_index('ix_analysis_jobs_status', 'analysis_jobs', ['status'])

    # 2. security_events table
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('job_id', sa.String(36), sa.ForeignKey('analysis_jobs.id', ondelete='CASCADE'), nullable=True),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('source_channel', sa.String(32), nullable=False, server_default='PCAP_BATCH'),
        sa.Column('predicted_family', sa.String(64), nullable=False),
        sa.Column('class_confidence', sa.Float(), nullable=False),
        sa.Column('normalized_anomaly_score', sa.Float(), nullable=False),
        sa.Column('is_statistical_anomaly', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(32), nullable=False),
        sa.Column('triage_status', sa.String(32), nullable=False),
        sa.Column('class_probabilities', sa.JSON(), nullable=False),
        sa.Column('feature_vector', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_security_events_job_id', 'security_events', ['job_id'])
    op.create_index('ix_security_events_event_timestamp', 'security_events', ['event_timestamp'])
    op.create_index('ix_security_events_source_channel', 'security_events', ['source_channel'])
    op.create_index('ix_security_events_predicted_family', 'security_events', ['predicted_family'])
    op.create_index('ix_security_events_is_statistical_anomaly', 'security_events', ['is_statistical_anomaly'])
    op.create_index('ix_security_events_risk_score', 'security_events', ['risk_score'])
    op.create_index('ix_security_events_severity', 'security_events', ['severity'])
    op.create_index('ix_security_events_triage_status', 'security_events', ['triage_status'])
    op.create_index('ix_security_events_time_severity', 'security_events', ['event_timestamp', 'severity'])
    op.create_index('ix_security_events_time_family', 'security_events', ['event_timestamp', 'predicted_family'])
    op.create_index('ix_security_events_time_status', 'security_events', ['event_timestamp', 'triage_status'])

    # 3. flow_provenance table
    op.create_table(
        'flow_provenance',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('event_id', sa.String(36), sa.ForeignKey('security_events.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('flow_id', sa.String(255), nullable=False),
        sa.Column('src_ip', sa.String(45), nullable=False),
        sa.Column('dst_ip', sa.String(45), nullable=False),
        sa.Column('src_port', sa.Integer(), nullable=False),
        sa.Column('dst_port', sa.Integer(), nullable=False),
        sa.Column('ip_proto', sa.Integer(), nullable=False),
        sa.Column('protocol_name', sa.String(16), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('duration_ms', sa.Float(), nullable=False),
        sa.Column('total_packets', sa.Integer(), nullable=False),
        sa.Column('total_bytes', sa.BigInteger(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_flow_provenance_event_id', 'flow_provenance', ['event_id'])
    op.create_index('ix_flow_provenance_flow_id', 'flow_provenance', ['flow_id'])
    op.create_index('ix_flow_provenance_src_ip', 'flow_provenance', ['src_ip'])
    op.create_index('ix_flow_provenance_dst_ip', 'flow_provenance', ['dst_ip'])
    op.create_index('ix_flow_provenance_src_port', 'flow_provenance', ['src_port'])
    op.create_index('ix_flow_provenance_dst_port', 'flow_provenance', ['dst_port'])
    op.create_index('ix_flow_provenance_protocol_name', 'flow_provenance', ['protocol_name'])

    # 4. model_decisions table
    op.create_table(
        'model_decisions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('event_id', sa.String(36), sa.ForeignKey('security_events.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('supervised_model_key', sa.String(64), nullable=False),
        sa.Column('anomaly_model_key', sa.String(64), nullable=False),
        sa.Column('raw_decision_score', sa.Float(), nullable=False),
        sa.Column('calibrated_threshold', sa.Float(), nullable=True),
        sa.Column('policy_version', sa.String(32), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_model_decisions_event_id', 'model_decisions', ['event_id'])
    op.create_index('ix_model_decisions_supervised_key', 'model_decisions', ['supervised_model_key'])
    op.create_index('ix_model_decisions_anomaly_key', 'model_decisions', ['anomaly_model_key'])

    # 5. alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('event_id', sa.String(36), sa.ForeignKey('security_events.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('alert_type', sa.String(64), nullable=False),
        sa.Column('severity', sa.String(32), nullable=False),
        sa.Column('disposition', sa.String(32), nullable=False, server_default='OPEN'),
        sa.Column('analyst_notes', sa.Text(), nullable=True),
        sa.Column('policy_version_applied', sa.String(32), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_alerts_event_id', 'alerts', ['event_id'])
    op.create_index('ix_alerts_alert_type', 'alerts', ['alert_type'])
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    op.create_index('ix_alerts_disposition', 'alerts', ['disposition'])
    op.create_index('ix_alerts_status_severity', 'alerts', ['disposition', 'severity'])

    # 6. alert_history table (Append-only audit trail)
    op.create_table(
        'alert_history',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('alert_id', sa.String(36), sa.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('previous_disposition', sa.String(32), nullable=True),
        sa.Column('new_disposition', sa.String(32), nullable=False),
        sa.Column('actor_id', sa.String(64), nullable=False, server_default='system'),
        sa.Column('action_note', sa.Text(), nullable=True),
    )
    op.create_index('ix_alert_history_alert_id', 'alert_history', ['alert_id'])
    op.create_index('ix_alert_history_timestamp', 'alert_history', ['timestamp'])


def downgrade() -> None:
    op.drop_table('alert_history')
    op.drop_table('alerts')
    op.drop_table('model_decisions')
    op.drop_table('flow_provenance')
    op.drop_table('security_events')
    op.drop_table('analysis_jobs')
