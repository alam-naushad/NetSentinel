"""SSE Streaming and Ingestion Status API routes.

Provides:
    GET /api/v1/zeek/stream           — SSE endpoint for live Zeek events
    GET /api/v1/zeek/ingestion/status — Ingestion worker status and counters
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from app.schemas.zeek import (
    ZeekIngestionBatchInfo,
    ZeekIngestionCounters,
    ZeekIngestionStatus,
    ZeekTrackedFile,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/zeek", tags=["zeek-stream"])


def _get_ingestion_context(request: Request):
    """Retrieve the ingestion context stored on the app state."""
    return getattr(request.app.state, "zeek_ingestion", None)


@router.get("/stream")
async def zeek_sse_stream(
    request: Request,
    last_event_id: str | None = Query(
        None,
        description="Resume from this composite event ID (session_id:sequence_id)",
    ),
):
    """Server-Sent Events endpoint for live Zeek connection telemetry.

    Events are delivered in the format:
        id: <session_id>:<sequence_id>
        event: zeek_connection
        data: { ... }

    SSE replay is guaranteed only within the current process session.
    After process restart, the client should recover missed events
    through the historical telemetry API (GET /api/v1/telemetry/events).
    """
    ctx = _get_ingestion_context(request)
    if ctx is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "Real-time Zeek ingestion is not enabled"},
        )

    broadcaster = ctx["broadcaster"]

    # Check Last-Event-ID from header (takes precedence)
    header_id = request.headers.get("Last-Event-ID") or last_event_id

    # Try to subscribe
    try:
        subscriber_id, queue = await broadcaster.subscribe(last_event_id=header_id)
    except RuntimeError:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many SSE clients connected"},
        )

    async def event_generator() -> AsyncGenerator:
        try:
            # Initial connection metadata
            yield {
                "event": "connected",
                "data": f'{{"session_id": "{broadcaster.session_id}", "replay_supported": true}}',
                "retry": 3000,
            }

            heartbeat_interval = ctx.get("heartbeat_sec", 15.0)
            status_interval = 30.0
            last_status = asyncio.get_event_loop().time()

            while True:
                try:
                    event = await asyncio.wait_for(
                        queue.get(), timeout=heartbeat_interval
                    )

                    yield {
                        "id": event.sse_id,
                        "event": event.event_type,
                        "data": event.to_sse_data(),
                    }

                except asyncio.TimeoutError:
                    # Send heartbeat comment
                    yield {"comment": "heartbeat"}

                # Periodic status pulse
                now = asyncio.get_event_loop().time()
                if now - last_status >= status_interval:
                    last_status = now
                    worker = ctx.get("worker")
                    status_data = '{}'
                    if worker:
                        status_data = (
                            f'{{"status": "running", '
                            f'"queue_depth": {ctx["queue"].qsize()}, '
                            f'"connected_clients": {broadcaster.client_count}}}'
                        )
                    yield {
                        "event": "ingestion_status",
                        "data": status_data,
                    }

        except asyncio.CancelledError:
            pass
        finally:
            await broadcaster.unsubscribe(subscriber_id)

    return EventSourceResponse(event_generator())


@router.get("/ingestion/status", response_model=ZeekIngestionStatus)
async def zeek_ingestion_status(request: Request):
    """Returns current ingestion worker state and observable counters."""
    from app.core.config import settings

    ctx = _get_ingestion_context(request)

    if ctx is None:
        return ZeekIngestionStatus(
            enabled=False,
            status="disabled",
            spool_directory=settings.ZEEK_SPOOL_DIR,
            counters=ZeekIngestionCounters(),
            latest_batch=ZeekIngestionBatchInfo(),
        )

    tailer = ctx.get("tailer")
    worker = ctx.get("worker")
    broadcaster = ctx.get("broadcaster")
    queue = ctx.get("queue")
    start_time = ctx.get("start_time", 0.0)

    import time
    uptime = time.time() - start_time if start_time else 0.0

    # Determine status
    if tailer and tailer.is_running:
        status = "running"
    elif tailer and not tailer._paused.is_set():
        status = "paused"
    else:
        status = "stopped"

    # Build counters
    t_counters = tailer.counters if tailer else None
    w_counters = worker.counters if worker else None

    counters = ZeekIngestionCounters(
        records_read=t_counters.records_read if t_counters else 0,
        records_parsed=t_counters.records_parsed if t_counters else 0,
        records_malformed=t_counters.records_malformed if t_counters else 0,
        records_duplicate=w_counters.records_duplicate if w_counters else 0,
        records_persisted=w_counters.records_persisted if w_counters else 0,
        batches_persisted=w_counters.batches_persisted if w_counters else 0,
        batches_failed=w_counters.batches_failed if w_counters else 0,
        persist_errors=w_counters.persist_errors if w_counters else 0,
        queue_depth=queue.qsize() if queue else 0,
        queue_high_watermark=w_counters.queue_high_watermark if w_counters else 0,
        sse_clients_connected=broadcaster.client_count if broadcaster else 0,
        sse_events_published=broadcaster.total_events_published if broadcaster else 0,
        sse_events_dropped=broadcaster.total_events_dropped if broadcaster else 0,
    )

    latest_batch = ZeekIngestionBatchInfo(
        ingestion_lag_ms=w_counters.ingestion_lag_ms if w_counters else 0.0,
        flush_latency_ms=w_counters.batch_flush_latency_ms if w_counters else 0.0,
        records_in_batch=w_counters.last_batch_size if w_counters else 0,
    )

    # Tracked files from tailer state
    tracked_files = []
    if tailer:
        for name, state in tailer._file_states.items():
            tracked_files.append(ZeekTrackedFile(
                file_name=name,
                byte_offset=state.byte_offset,
                lines_processed=state.lines_read,
            ))

    return ZeekIngestionStatus(
        enabled=True,
        status=status,
        spool_directory=settings.ZEEK_SPOOL_DIR,
        uptime_seconds=round(uptime, 1),
        counters=counters,
        latest_batch=latest_batch,
        tracked_files=tracked_files,
        sse_session_id=broadcaster.session_id if broadcaster else None,
    )
