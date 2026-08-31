"""Durable Offset Tracker for Zeek spool ingestion.

Persists and recovers file read positions via the ``ingestion_checkpoints``
PostgreSQL table.  Checkpoint updates happen **within the same database
transaction** that persists the corresponding Zeek events, enforcing:

    DB commit succeeds  →  durable checkpoint advances
    DB transaction fails →  durable checkpoint does NOT advance
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.ingestion_checkpoint import IngestionCheckpoint

logger = logging.getLogger(__name__)


class CheckpointState:
    """In-memory snapshot of a single file's checkpoint, loaded from DB."""

    __slots__ = ("file_name", "byte_offset", "lines_processed", "file_inode", "last_zeek_uid")

    def __init__(
        self,
        file_name: str,
        byte_offset: int = 0,
        lines_processed: int = 0,
        file_inode: int | None = None,
        last_zeek_uid: str | None = None,
    ):
        self.file_name = file_name
        self.byte_offset = byte_offset
        self.lines_processed = lines_processed
        self.file_inode = file_inode
        self.last_zeek_uid = last_zeek_uid


class OffsetTracker:
    """Manages durable ingestion checkpoints in PostgreSQL.

    All checkpoint writes go through :meth:`advance_checkpoint` which operates
    on the caller-supplied ``AsyncSession``.  This allows the caller (the
    ``IngestionWorker``) to commit events and checkpoint atomically.
    """

    def __init__(self, spool_directory: str):
        self.spool_directory = spool_directory

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    async def load_checkpoints(self, session: AsyncSession) -> Dict[str, CheckpointState]:
        """Load all checkpoints for the configured spool directory.

        Returns a mapping of ``file_name -> CheckpointState``.
        """
        stmt = select(IngestionCheckpoint).where(
            IngestionCheckpoint.spool_directory == self.spool_directory,
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

        states: Dict[str, CheckpointState] = {}
        for row in rows:
            states[row.file_name] = CheckpointState(
                file_name=row.file_name,
                byte_offset=row.byte_offset,
                lines_processed=row.lines_processed,
                file_inode=row.file_inode,
                last_zeek_uid=row.last_zeek_uid,
            )
            logger.info(
                "Restored checkpoint %s/%s: offset=%d, lines=%d",
                self.spool_directory,
                row.file_name,
                row.byte_offset,
                row.lines_processed,
            )
        return states

    # ------------------------------------------------------------------
    # Transactional checkpoint advance
    # ------------------------------------------------------------------

    async def advance_checkpoint(
        self,
        session: AsyncSession,
        *,
        file_name: str,
        byte_offset: int,
        lines_processed: int,
        file_inode: Optional[int] = None,
        last_zeek_uid: Optional[str] = None,
    ) -> None:
        """Upsert the durable checkpoint **within the caller's transaction**.

        This MUST be called before ``session.commit()`` so that the checkpoint
        and the event rows are committed (or rolled back) atomically.
        """
        stmt = select(IngestionCheckpoint).where(
            IngestionCheckpoint.spool_directory == self.spool_directory,
            IngestionCheckpoint.file_name == file_name,
        )
        result = await session.execute(stmt)
        row = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if row is None:
            row = IngestionCheckpoint(
                spool_directory=self.spool_directory,
                file_name=file_name,
                file_inode=file_inode,
                byte_offset=byte_offset,
                lines_processed=lines_processed,
                last_zeek_uid=last_zeek_uid,
                updated_at=now,
            )
            session.add(row)
        else:
            row.byte_offset = byte_offset
            row.lines_processed = lines_processed
            row.file_inode = file_inode
            row.last_zeek_uid = last_zeek_uid
            row.updated_at = now

        await session.flush()

    # ------------------------------------------------------------------
    # Rotation reset
    # ------------------------------------------------------------------

    async def reset_checkpoint(
        self,
        session: AsyncSession,
        *,
        file_name: str,
        file_inode: Optional[int] = None,
    ) -> None:
        """Reset a checkpoint to offset 0 (e.g. after log rotation).

        Also committed within the caller's transaction.
        """
        await self.advance_checkpoint(
            session,
            file_name=file_name,
            byte_offset=0,
            lines_processed=0,
            file_inode=file_inode,
            last_zeek_uid=None,
        )
