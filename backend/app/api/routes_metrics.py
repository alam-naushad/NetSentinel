"""Operational Metrics API Endpoint for Hardened Capstone Deployment.

Provides:
    GET /api/v1/metrics — Operational metrics and platform telemetry.

Security Notice:
    Exposes only aggregated operational telemetry. Internal database credentials,
    filesystem paths, memory pointers, and sensitive configuration values are omitted.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict
from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.core.config import settings
from app.core.database import check_database_connection
from app.services.model_registry import get_model_registry

router = APIRouter(tags=["metrics"])

# Process start time for uptime tracking
PROCESS_START_TIME = time.time()


class SystemMetricsResponse(BaseModel):
    """Operational telemetry payload."""
    status: str
    environment: str
    uptime_seconds: float
    platform_version: str
    persistence_connected: bool
    database_dialect: str | None = None
    models_loaded: int = 0
    sse_clients_connected: int = 0
    zeek_spool_enabled: bool = False
    zeek_records_persisted: int = 0
    zeek_queue_depth: int = 0
    zeek_ingestion_lag_ms: float = 0.0


@router.get("/metrics", response_model=SystemMetricsResponse)
async def get_system_metrics(request: Request) -> SystemMetricsResponse:
    """Returns aggregated operational telemetry for monitoring."""
    uptime = round(time.time() - PROCESS_START_TIME, 1)

    # 1. Database status
    db_status = await check_database_connection()
    persistence_connected = db_status.get("connected", False)
    db_dialect = db_status.get("dialect")

    # 2. Model registry status
    registry = get_model_registry()
    models_loaded = len(registry._cache)

    # 3. Zeek live telemetry status
    ctx = getattr(request.app.state, "zeek_ingestion", None)
    sse_clients = 0
    records_persisted = 0
    queue_depth = 0
    ingestion_lag_ms = 0.0
    spool_enabled = settings.ZEEK_SPOOL_ENABLED

    if ctx is not None:
        broadcaster = ctx.get("broadcaster")
        worker = ctx.get("worker")
        queue = ctx.get("queue")

        if broadcaster:
            sse_clients = broadcaster.client_count
        if worker and hasattr(worker, "counters"):
            records_persisted = worker.counters.records_persisted
            ingestion_lag_ms = worker.counters.ingestion_lag_ms
        if queue:
            queue_depth = queue.qsize()

    return SystemMetricsResponse(
        status="healthy" if persistence_connected or not settings.DATABASE_REQUIRED else "degraded",
        environment=settings.ENVIRONMENT,
        uptime_seconds=uptime,
        platform_version=settings.APP_VERSION,
        persistence_connected=persistence_connected,
        database_dialect=db_dialect,
        models_loaded=models_loaded,
        sse_clients_connected=sse_clients,
        zeek_spool_enabled=spool_enabled,
        zeek_records_persisted=records_persisted,
        zeek_queue_depth=queue_depth,
        zeek_ingestion_lag_ms=round(ingestion_lag_ms, 2),
    )
