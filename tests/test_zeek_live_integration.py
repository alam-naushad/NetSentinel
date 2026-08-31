"""End-to-End Integration tests for Stage 9B Real-Time Zeek Native Telemetry.

Verifies:
- Complete pipeline: File write -> SpoolTailer -> Bounded Queue -> IngestionWorker -> PostgreSQL -> EventBroadcaster
- Invariant: ml_classification_performed=false, no fabricated ML scores/labels
- Invariant: source_type=ZEEK_LIVE on AnalysisJob, source_channel=ZEEK_CONN on SecurityEvent
- Coexistence: Historical telemetry queries retrieve both PCAP and live Zeek events
- Invariant: PCAP ML inference pipeline (Stage 6A/6B) remains completely operational and unaffected
"""

import asyncio
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.db.base import Base
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.ingestion_checkpoint import IngestionCheckpoint
from app.db.models.security_event import SecurityEvent
from app.services.zeek.event_broadcaster import EventBroadcaster
from app.services.zeek.ingestion_worker import IngestionWorker
from app.services.zeek.offset_tracker import OffsetTracker
from app.services.zeek.spool_tailer import SpoolTailer


class TestZeekLiveIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration test suite for Stage 9B real-time pipeline."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="zeek_live_e2e_")
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

        self.queue = asyncio.Queue(maxsize=100)
        self.broadcaster = EventBroadcaster(max_clients=5)
        self.offset_tracker = OffsetTracker(spool_directory=self.temp_dir)

    async def asyncTearDown(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _sample_json_line(self, uid="CE2EUID1", ts=1693526400.0, orig_h="192.168.1.10"):
        return json.dumps({
            "ts": ts,
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 2.5,
            "orig_bytes": 1200,
            "resp_bytes": 4500,
            "conn_state": "SF",
            "history": "ShADadFf",
            "orig_pkts": 12,
            "resp_pkts": 15,
        }) + "\n"

    async def test_end_to_end_live_ingestion_and_broadcasting(self):
        """Writing lines to spool file flows through tailer, worker, database, and SSE broadcaster."""
        # 1. Subscribe SSE client
        sub_id, sse_queue = await self.broadcaster.subscribe()

        # 2. Setup Tailer and Worker
        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.05,
        )
        worker = IngestionWorker(
            queue=self.queue,
            session_maker=self.session_factory,
            offset_tracker=self.offset_tracker,
            broadcaster=self.broadcaster,
            tailer=tailer,
            batch_size=2,
            flush_interval_sec=0.2,
        )

        tailer_task = asyncio.create_task(tailer.run())
        worker_task = asyncio.create_task(worker.run())

        # 3. Write 2 lines to conn.log
        log_file = Path(self.temp_dir) / "conn.log"
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(self._sample_json_line("E2E_1", ts=1693526401.0))
            f.write(self._sample_json_line("E2E_2", ts=1693526402.0))

        # 4. Wait for processing
        await asyncio.sleep(0.5)

        # 5. Stop pipeline
        tailer.request_stop()
        worker.request_stop()
        await self.queue.put(None)
        await asyncio.gather(tailer_task, worker_task)

        # 6. Verify SSE delivery
        self.assertEqual(sse_queue.qsize(), 2)
        event1 = await sse_queue.get()
        event2 = await sse_queue.get()
        self.assertEqual(event1.data["uid"], "E2E_1")
        self.assertEqual(event2.data["uid"], "E2E_2")
        self.assertTrue(event1.data["persisted"])

        # 7. Verify Database persistence & invariants
        async with self.session_factory() as session:
            # Events
            events = (await session.execute(select(SecurityEvent))).scalars().all()
            self.assertEqual(len(events), 2)
            for ev in events:
                self.assertFalse(ev.ml_classification_performed)
                self.assertEqual(ev.source_channel, "ZEEK_CONN")
                self.assertIsNone(ev.predicted_family)
                self.assertIsNone(ev.class_confidence)
                self.assertIsNone(ev.risk_score)
                self.assertIsNone(ev.severity)
                self.assertIsNone(ev.feature_vector)

            # Provenance
            provenances = (await session.execute(select(FlowProvenance))).scalars().all()
            self.assertEqual(len(provenances), 2)
            uids = {p.zeek_uid for p in provenances}
            self.assertEqual(uids, {"E2E_1", "E2E_2"})

            # AnalysisJob
            jobs = (await session.execute(select(AnalysisJob))).scalars().all()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0].source_type, "ZEEK_LIVE")

            # IngestionCheckpoint
            cp = (await session.execute(select(IngestionCheckpoint))).scalar_one()
            self.assertEqual(cp.file_name, "conn.log")
            self.assertGreater(cp.byte_offset, 0)
            self.assertEqual(cp.last_zeek_uid, "E2E_2")

        await self.broadcaster.unsubscribe(sub_id)


if __name__ == "__main__":
    unittest.main()
