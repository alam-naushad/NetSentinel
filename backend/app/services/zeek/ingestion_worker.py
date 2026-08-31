"""Ingestion Worker — consumes parsed Zeek records, micro-batches, and persists.

Core invariants (per user corrections):

1. **Durable checkpoint in same transaction** — the ``IngestionCheckpoint``
   row is updated within the same PostgreSQL transaction that persists the
   ``SecurityEvent`` + ``FlowProvenance`` + ``AnalysisJob`` rows.

2. **No data loss on DB failure** — valid records are never dropped.  If
   PostgreSQL is unavailable the worker pauses the tailer, waits for
   recovery, and retries.  The durable checkpoint never advances for an
   uncommitted batch.

3. **Graceful shutdown** — on shutdown, the worker drains the queue and
   attempts to persist remaining records.  If the DB is down, it exits
   without advancing the checkpoint so that restart resumes from the last
   committed offset.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.security_event import SecurityEvent
from app.services.zeek.event_broadcaster import EventBroadcaster
from app.services.zeek.offset_tracker import OffsetTracker
from app.services.zeek.spool_tailer import SpoolTailer
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord

logger = logging.getLogger(__name__)

DB_HEALTH_CHECK_INTERVAL = 10.0  # seconds between DB health probes when paused


class IngestionCounters:
    """Observable counters for the ingestion worker."""

    def __init__(self):
        self.records_persisted: int = 0
        self.records_duplicate: int = 0
        self.batches_persisted: int = 0
        self.batches_failed: int = 0
        self.persist_errors: int = 0
        self.queue_high_watermark: int = 0
        self.ingestion_lag_ms: float = 0.0
        self.batch_flush_latency_ms: float = 0.0
        self.last_batch_size: int = 0


class IngestionWorker:
    """Consumes parsed Zeek records from a queue, batches them, and persists
    to PostgreSQL with atomic checkpoint advancement."""

    def __init__(
        self,
        queue: asyncio.Queue,
        session_maker: async_sessionmaker[AsyncSession],
        offset_tracker: OffsetTracker,
        broadcaster: EventBroadcaster,
        tailer: SpoolTailer,
        *,
        batch_size: int = 50,
        flush_interval_sec: float = 2.0,
        dedup_cache_size: int = 10_000,
    ):
        self._queue = queue
        self._session_maker = session_maker
        self._offset_tracker = offset_tracker
        self._broadcaster = broadcaster
        self._tailer = tailer
        self._batch_size = batch_size
        self._flush_interval = flush_interval_sec
        self._dedup_cache_size = dedup_cache_size

        self._stop_event = asyncio.Event()
        self._draining = False
        self.counters = IngestionCounters()

        # LRU dedup cache: (file_name, zeek_uid) -> True
        self._dedup_cache: OrderedDict[tuple[str, str], bool] = OrderedDict()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main consumption loop."""
        logger.info("IngestionWorker starting (batch=%d, flush=%.1fs)",
                     self._batch_size, self._flush_interval)
        batch: List[Dict[str, Any]] = []
        batch_start: float | None = None

        try:
            while True:
                if self._stop_event.is_set() and self._queue.empty():
                    break

                # Track queue depth
                qsize = self._queue.qsize()
                if qsize > self.counters.queue_high_watermark:
                    self.counters.queue_high_watermark = qsize

                # Try to get a record
                timeout = self._time_until_flush(batch_start)
                try:
                    item = await asyncio.wait_for(
                        self._queue.get(), timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    # Flush partial batch on timer
                    if batch:
                        await self._flush_batch(batch)
                        batch = []
                        batch_start = None
                    continue
                except asyncio.CancelledError:
                    # Graceful drain: flush remaining
                    if batch:
                        await self._flush_batch(batch)
                    raise

                if item is None:
                    # Poison pill — drain
                    if batch:
                        await self._flush_batch(batch)
                    break

                # Dedup check
                rec: ZeekConnectionRecord = item["_record"]
                file_name: str = item["_file_name"]
                dedup_key = (file_name, rec.uid)

                if dedup_key in self._dedup_cache:
                    self.counters.records_duplicate += 1
                    continue

                # Add to dedup cache (LRU eviction)
                self._dedup_cache[dedup_key] = True
                if len(self._dedup_cache) > self._dedup_cache_size:
                    self._dedup_cache.popitem(last=False)

                batch.append(item)
                if batch_start is None:
                    batch_start = time.monotonic()

                # Flush if batch full
                if len(batch) >= self._batch_size:
                    await self._flush_batch(batch)
                    batch = []
                    batch_start = None

        except asyncio.CancelledError:
            logger.info("IngestionWorker cancelled — draining queue...")
            # Drain remaining queue items
            remaining = list(batch)
            while not self._queue.empty():
                try:
                    item = self._queue.get_nowait()
                    if item is not None:
                        remaining.append(item)
                except asyncio.QueueEmpty:
                    break
            if remaining:
                await self._flush_batch(remaining)
            raise
        except Exception:
            logger.exception("IngestionWorker unexpected error")
        finally:
            logger.info(
                "IngestionWorker stopped. persisted=%d batches=%d failed=%d dups=%d",
                self.counters.records_persisted,
                self.counters.batches_persisted,
                self.counters.batches_failed,
                self.counters.records_duplicate,
            )

    def request_stop(self) -> None:
        """Signal the worker to drain and stop."""
        self._stop_event.set()

    async def drain_and_stop(self) -> None:
        """Put poison pill and wait for the queue to drain."""
        self._draining = True
        await self._queue.put(None)  # poison pill

    # ------------------------------------------------------------------
    # Internal: flush batch
    # ------------------------------------------------------------------

    async def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Persist a batch of records with atomic checkpoint advancement.

        On DB failure: pauses the tailer and waits for recovery.
        Never drops valid records. Never advances checkpoint for
        uncommitted batches.
        """
        if not batch:
            return

        flush_start = time.monotonic()
        records = [(item["_record"], item["_file_name"], item["_byte_offset"]) for item in batch]

        while True:
            try:
                async with self._session_maker() as session:
                    async with session.begin():
                        # 1. Create AnalysisJob
                        job = AnalysisJob(
                            source_type="ZEEK_LIVE",
                            filename="spool_ingestion",
                            file_size_bytes=0,
                            total_flows_extracted=len(records),
                            total_flows_analyzed=len(records),
                            anomalies_flagged=0,
                            processing_time_ms=0.0,
                            status="COMPLETED",
                        )
                        session.add(job)
                        await session.flush()

                        # 2. Map records to SecurityEvent + FlowProvenance
                        events = []
                        latest_offset_per_file: Dict[str, tuple[int, str | None]] = {}

                        for rec, file_name, byte_offset in records:
                            event = self._map_record_to_event(rec, job.id)
                            events.append(event)

                            # Track the highest offset per file for checkpoint
                            current = latest_offset_per_file.get(file_name)
                            if current is None or byte_offset >= current[0]:
                                latest_offset_per_file[file_name] = (byte_offset, rec.uid)

                        session.add_all(events)
                        await session.flush()

                        # 3. Advance durable checkpoint(s) — SAME TRANSACTION
                        for file_name, (offset, last_uid) in latest_offset_per_file.items():
                            await self._offset_tracker.advance_checkpoint(
                                session,
                                file_name=file_name,
                                byte_offset=offset,
                                lines_processed=offset,  # approximate
                                last_zeek_uid=last_uid,
                            )

                    # Transaction committed successfully
                    # session.begin() context handles commit

                # Update counters
                flush_ms = (time.monotonic() - flush_start) * 1000
                self.counters.records_persisted += len(records)
                self.counters.batches_persisted += 1
                self.counters.batch_flush_latency_ms = flush_ms
                self.counters.last_batch_size = len(records)

                # Compute ingestion lag from latest Zeek timestamp
                latest_ts = max(rec.ts for rec, _, _ in records)
                lag_ms = (time.time() - latest_ts) * 1000
                self.counters.ingestion_lag_ms = lag_ms

                logger.info(
                    "Persisted batch: %d records, flush=%.1fms, lag=%.1fms, job=%s",
                    len(records), flush_ms, lag_ms, job.id,
                )

                # Resume tailer if it was paused
                self._tailer.resume()

                # 4. Broadcast to SSE subscribers
                for rec, file_name, _ in records:
                    await self._broadcast_record(rec)

                return  # Success — exit retry loop

            except Exception as e:
                self.counters.persist_errors += 1
                logger.error(
                    "Batch persistence failed (%d records): %s",
                    len(records), e,
                )

                if self._draining or self._stop_event.is_set():
                    # During shutdown: don't block forever, but also don't
                    # advance the checkpoint.  Log and exit.
                    self.counters.batches_failed += 1
                    logger.warning(
                        "DB unavailable during shutdown — %d records NOT "
                        "persisted. Checkpoint NOT advanced. They will be "
                        "re-read on next startup from the durable offset.",
                        len(records),
                    )
                    return

                # Pause tailer and wait for DB recovery
                self._tailer.pause()
                logger.warning(
                    "Pausing ingestion — waiting for DB recovery "
                    "(check every %.0fs)...", DB_HEALTH_CHECK_INTERVAL,
                )
                await asyncio.sleep(DB_HEALTH_CHECK_INTERVAL)
                # Loop back and retry the same batch

    # ------------------------------------------------------------------
    # Record mapping (reuses Stage 8 telemetry service patterns)
    # ------------------------------------------------------------------

    def _map_record_to_event(
        self, rec: ZeekConnectionRecord, job_id: uuid.UUID
    ) -> SecurityEvent:
        """Convert a ZeekConnectionRecord to SecurityEvent + FlowProvenance."""
        event_dt = datetime.fromtimestamp(rec.ts, tz=timezone.utc)
        duration_sec = rec.duration if rec.duration is not None else 0.0
        end_dt = datetime.fromtimestamp(rec.ts + duration_sec, tz=timezone.utc)
        duration_ms = round(duration_sec * 1000.0, 3)

        proto_str = rec.proto.upper()
        ip_proto = 6 if rec.proto.lower() == "tcp" else 17 if rec.proto.lower() == "udp" else 1
        flow_id = (
            f"{proto_str}_{rec.id_orig_h}_{rec.id_orig_p}_"
            f"{rec.id_resp_h}_{rec.id_resp_p}_{int(rec.ts * 1_000_000)}"
        )

        event = SecurityEvent(
            job_id=job_id,
            event_timestamp=event_dt,
            source_channel="ZEEK_CONN",
            ml_classification_performed=False,
            predicted_family=None,
            class_confidence=None,
            normalized_anomaly_score=None,
            is_statistical_anomaly=False,
            risk_score=None,
            severity=None,
            triage_status=None,
            class_probabilities=None,
            feature_vector=None,
        )

        event.provenance = FlowProvenance(
            flow_id=flow_id,
            src_ip=rec.id_orig_h,
            dst_ip=rec.id_resp_h,
            src_port=rec.id_orig_p,
            dst_port=rec.id_resp_p,
            ip_proto=ip_proto,
            protocol_name=proto_str,
            start_time=event_dt,
            end_time=end_dt,
            duration_ms=duration_ms,
            total_packets=(rec.orig_pkts or 0) + (rec.resp_pkts or 0),
            total_bytes=(rec.orig_bytes or 0) + (rec.resp_bytes or 0),
            zeek_uid=rec.uid,
            conn_state=rec.conn_state,
            history=rec.history,
            service=rec.service,
            missed_bytes=rec.missed_bytes,
            zeek_metadata={
                "local_orig": rec.local_orig,
                "local_resp": rec.local_resp,
                "orig_ip_bytes": rec.orig_ip_bytes,
                "resp_ip_bytes": rec.resp_ip_bytes,
                "tunnel_parents": rec.tunnel_parents,
            },
        )

        return event

    # ------------------------------------------------------------------
    # SSE broadcasting
    # ------------------------------------------------------------------

    async def _broadcast_record(self, rec: ZeekConnectionRecord) -> None:
        """Publish a Zeek connection record to SSE subscribers."""
        try:
            await self._broadcaster.broadcast(
                "zeek_connection",
                {
                    "ts": rec.ts,
                    "uid": rec.uid,
                    "src_ip": rec.id_orig_h,
                    "src_port": rec.id_orig_p,
                    "dst_ip": rec.id_resp_h,
                    "dst_port": rec.id_resp_p,
                    "proto": rec.proto,
                    "service": rec.service,
                    "duration_sec": rec.duration,
                    "orig_bytes": rec.orig_bytes,
                    "resp_bytes": rec.resp_bytes,
                    "conn_state": rec.conn_state,
                    "orig_pkts": rec.orig_pkts,
                    "resp_pkts": rec.resp_pkts,
                    "history": rec.history,
                    "event_timestamp": datetime.fromtimestamp(
                        rec.ts, tz=timezone.utc
                    ).isoformat(),
                    "persisted": True,
                },
            )
        except Exception:
            logger.debug("Failed to broadcast record %s", rec.uid, exc_info=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _time_until_flush(self, batch_start: float | None) -> float:
        """Seconds until the current partial batch should be flushed."""
        if batch_start is None:
            return self._flush_interval
        elapsed = time.monotonic() - batch_start
        remaining = self._flush_interval - elapsed
        return max(0.05, remaining)
