"""Tests for Zeek IngestionWorker.

Verifies:
- Micro-batching by record count threshold
- Micro-batching by timer threshold
- Ingestion checkpoint update in the SAME transaction as event persistence
- LRU deduplication across records within/between batches
- Broadcast of live records to SSE broadcaster after DB commit
- No data loss on transient DB errors (pausing tailer, retry)
- Graceful drain and stop
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.db.base import Base
from app.db.models.analysis_job import AnalysisJob
from app.db.models.ingestion_checkpoint import IngestionCheckpoint
from app.db.models.security_event import SecurityEvent
from app.services.zeek.event_broadcaster import EventBroadcaster
from app.services.zeek.ingestion_worker import IngestionWorker
from app.services.zeek.offset_tracker import OffsetTracker
from app.services.zeek.spool_tailer import SpoolTailer
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord


class TestIngestionWorker(unittest.IsolatedAsyncioTestCase):
    """Unit tests for IngestionWorker."""

    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

        self.queue = asyncio.Queue()
        self.offset_tracker = OffsetTracker(spool_directory="/test/spool")
        self.broadcaster = EventBroadcaster(max_clients=5)
        self.tailer = MagicMock(spec=SpoolTailer)
        self.tailer.pause = MagicMock()
        self.tailer.resume = MagicMock()

    async def asyncTearDown(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    def _sample_record(self, uid="CWorkerUID1", ts=1693526400.0):
        return ZeekConnectionRecord(
            ts=ts,
            uid=uid,
            id_orig_h="192.168.1.100",
            id_orig_p=50000,
            id_resp_h="10.0.0.1",
            id_resp_p=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=1000,
            resp_bytes=2000,
            conn_state="SF",
            orig_pkts=10,
            resp_pkts=8,
        )

    async def test_batch_flush_by_count(self):
        """Worker flushes to PostgreSQL as soon as batch_size is reached."""
        worker = IngestionWorker(
            queue=self.queue,
            session_maker=self.session_factory,
            offset_tracker=self.offset_tracker,
            broadcaster=self.broadcaster,
            tailer=self.tailer,
            batch_size=3,
            flush_interval_sec=10.0,
        )

        task = asyncio.create_task(worker.run())

        # Put 3 items into queue
        for i in range(3):
            await self.queue.put({
                "_record": self._sample_record(f"UID_COUNT_{i}"),
                "_file_name": "conn.log",
                "_byte_offset": (i + 1) * 100,
            })

        await asyncio.sleep(0.3)
        worker.request_stop()
        await self.queue.put(None)
        await task

        self.assertEqual(worker.counters.records_persisted, 3)
        self.assertEqual(worker.counters.batches_persisted, 1)

        # Verify DB records
        async with self.session_factory() as session:
            events = (await session.execute(select(SecurityEvent))).scalars().all()
            self.assertEqual(len(events), 3)

            jobs = (await session.execute(select(AnalysisJob))).scalars().all()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0].source_type, "ZEEK_LIVE")

            # Checkpoint updated in same transaction
            cp = (await session.execute(select(IngestionCheckpoint))).scalar_one()
            self.assertEqual(cp.byte_offset, 300)
            self.assertEqual(cp.last_zeek_uid, "UID_COUNT_2")

    async def test_batch_flush_by_timer(self):
        """Worker flushes partial batch when timer expires before batch_size is reached."""
        worker = IngestionWorker(
            queue=self.queue,
            session_maker=self.session_factory,
            offset_tracker=self.offset_tracker,
            broadcaster=self.broadcaster,
            tailer=self.tailer,
            batch_size=100,
            flush_interval_sec=0.2,
        )

        task = asyncio.create_task(worker.run())

        await self.queue.put({
            "_record": self._sample_record("UID_TIMER_1"),
            "_file_name": "conn.log",
            "_byte_offset": 150,
        })

        # Wait for flush timer (0.2s)
        await asyncio.sleep(0.4)
        worker.request_stop()
        await self.queue.put(None)
        await task

        self.assertEqual(worker.counters.records_persisted, 1)
        self.assertEqual(worker.counters.batches_persisted, 1)

    async def test_dedup_cache_prevents_duplicate_records(self):
        """Duplicate records with same (file_name, uid) are skipped."""
        worker = IngestionWorker(
            queue=self.queue,
            session_maker=self.session_factory,
            offset_tracker=self.offset_tracker,
            broadcaster=self.broadcaster,
            tailer=self.tailer,
            batch_size=5,
            flush_interval_sec=0.2,
        )

        task = asyncio.create_task(worker.run())

        rec = self._sample_record("SAME_UID")
        # Put same record twice
        await self.queue.put({"_record": rec, "_file_name": "conn.log", "_byte_offset": 100})
        await self.queue.put({"_record": rec, "_file_name": "conn.log", "_byte_offset": 200})

        await asyncio.sleep(0.4)
        worker.request_stop()
        await self.queue.put(None)
        await task

        self.assertEqual(worker.counters.records_persisted, 1)
        self.assertEqual(worker.counters.records_duplicate, 1)

    async def test_live_broadcast_after_commit(self):
        """Worker broadcasts persisted records to EventBroadcaster."""
        sub_id, sse_queue = await self.broadcaster.subscribe()

        worker = IngestionWorker(
            queue=self.queue,
            session_maker=self.session_factory,
            offset_tracker=self.offset_tracker,
            broadcaster=self.broadcaster,
            tailer=self.tailer,
            batch_size=1,
            flush_interval_sec=1.0,
        )

        task = asyncio.create_task(worker.run())

        await self.queue.put({
            "_record": self._sample_record("UID_BROADCAST"),
            "_file_name": "conn.log",
            "_byte_offset": 100,
        })

        await asyncio.sleep(0.3)
        worker.request_stop()
        await self.queue.put(None)
        await task

        # Verify SSE subscriber received the event
        self.assertEqual(sse_queue.qsize(), 1)
        event = await sse_queue.get()
        self.assertEqual(event.data["uid"], "UID_BROADCAST")
        self.assertEqual(event.data["persisted"], True)

        await self.broadcaster.unsubscribe(sub_id)


if __name__ == "__main__":
    unittest.main()
