"""Ingestion Checkpoints

Revision ID: 0003_ingestion_checkpoints
Revises: 0002_zeek_native_telemetry
Create Date: 2026-08-31 09:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0003_ingestion_checkpoints'
down_revision: Union[str, None] = '0002_zeek_native_telemetry'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ingestion_checkpoints',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('spool_directory', sa.String(512), nullable=False),
        sa.Column('file_name', sa.String(255), nullable=False),
        sa.Column('file_inode', sa.BigInteger(), nullable=True),
        sa.Column('byte_offset', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('lines_processed', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('last_zeek_uid', sa.String(24), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('spool_directory', 'file_name', name='uq_checkpoint_spool_file'),
    )
    op.create_index('ix_ingestion_checkpoints_spool_directory',
                     'ingestion_checkpoints', ['spool_directory'])


def downgrade() -> None:
    op.drop_index('ix_ingestion_checkpoints_spool_directory',
                   table_name='ingestion_checkpoints')
    op.drop_table('ingestion_checkpoints')
