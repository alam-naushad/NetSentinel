"""Ingestion Checkpoint Model for durable file offset tracking.

Persists the last byte offset whose corresponding Zeek records were
successfully committed to PostgreSQL, enabling crash-recovery of
spool ingestion without data loss.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, GUID, TimestampMixin


class IngestionCheckpoint(Base, TimestampMixin):
    """Tracks durable file read positions for crash-recovery of spool ingestion.

    Invariant:
        The ``byte_offset`` stored here represents only the last position whose
        corresponding Zeek records were **successfully committed** to PostgreSQL
        within the same transaction that updates this checkpoint.  If the
        transaction fails, the checkpoint does not advance.
    """

    __tablename__ = "ingestion_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    spool_directory: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_inode: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    byte_offset: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    lines_processed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_zeek_uid: Mapped[str | None] = mapped_column(String(24), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint(
            "spool_directory", "file_name", name="uq_checkpoint_spool_file"
        ),
    )
