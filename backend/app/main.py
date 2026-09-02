"""FastAPI Application Entrypoint for AI Network Anomaly Detection Platform."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes_alerts import router as alerts_router
from app.api.routes_auth import router as auth_router
from app.api.routes_decisions import router as decisions_router
from app.api.routes_health import router as health_router
from app.api.routes_inference import router as inference_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_models import router as models_router
from app.api.routes_pcap import router as pcap_router
from app.api.routes_zeek import router as zeek_router
from app.api.routes_zeek_stream import router as zeek_stream_router
from app.api.routes_telemetry import router as telemetry_router
from app.core.config import settings
from app.core.database import check_database_connection
from app.core.logging_config import setup_logging
from app.core.security import (
    SecurityHeadersMiddleware,
    get_current_user,
    parse_cors_origins,
    validate_auth_configuration,
)
from app.services.model_registry import get_model_registry
from app.services.preprocessor import FeatureValidationError

# Initialize structured / console logging
setup_logging()
logger = logging.getLogger("backend.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown lifespan context."""
    logger.info(f"Initializing {settings.APP_NAME} (env={settings.ENVIRONMENT})...")

    # Security check on default credentials in production
    if settings.ENVIRONMENT == "production" and "soc_password" in settings.DATABASE_URL:
        logger.warning(
            "SECURITY WARNING: Default database credentials in use in production mode. "
            "Please configure POSTGRES_PASSWORD in environment variables."
        )

    # Validate authentication configuration (fail-closed in production)
    validate_auth_configuration()

    # 1. Check database connectivity
    db_status = await check_database_connection()
    if db_status["connected"]:
        logger.info(f"Database connection established ({db_status['dialect']}). Persistent storage active.")
    else:
        if settings.DATABASE_REQUIRED:
            err_msg = f"DATABASE_REQUIRED=true but database connection failed: {db_status.get('error')}"
            logger.critical(err_msg)
            raise RuntimeError(err_msg)
        else:
            logger.warning(
                f"Database unavailable. Running in explicit ephemeral mode (DATABASE_REQUIRED=false). Error: {db_status.get('error')}"
            )

    # 2. Preload & verify ML model integrity
    registry = get_model_registry()
    try:
        registry.validate_required_models_exist()
        sup = registry.get_default_supervised_model()
        anom = registry.get_default_anomaly_model()
        logger.info(
            f"Preloaded and verified default models: Supervised='{sup.key}', Anomaly='{anom.key}'"
        )
    except Exception as e:
        logger.critical(f"Model integrity / loading check failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(f"Fatal startup error: Model verification failed: {e}")
        else:
            logger.warning(f"Running without full default models preloaded: {e}")

    # 3. Start Zeek real-time ingestion pipeline (Stage 9B)
    ingestion_tasks = []
    if settings.ZEEK_SPOOL_ENABLED and db_status.get("connected"):
        try:
            import asyncio
            import time
            from app.core.database import get_async_session_maker
            from app.services.zeek.event_broadcaster import EventBroadcaster
            from app.services.zeek.ingestion_worker import IngestionWorker
            from app.services.zeek.offset_tracker import OffsetTracker
            from app.services.zeek.spool_tailer import SpoolTailer

            queue = asyncio.Queue(maxsize=settings.ZEEK_QUEUE_MAX_SIZE)
            session_maker = get_async_session_maker()

            broadcaster = EventBroadcaster(
                max_clients=settings.ZEEK_SSE_MAX_CLIENTS,
                replay_buffer_size=settings.ZEEK_SSE_REPLAY_BUFFER_SIZE,
            )

            offset_tracker = OffsetTracker(spool_directory=settings.ZEEK_SPOOL_DIR)

            # Load durable checkpoints from PostgreSQL
            initial_offsets = {}
            try:
                async with session_maker() as session:
                    checkpoints = await offset_tracker.load_checkpoints(session)
                    initial_offsets = {
                        name: cp.byte_offset for name, cp in checkpoints.items()
                    }
            except Exception as e:
                logger.warning("Could not load ingestion checkpoints: %s", e)

            tailer = SpoolTailer(
                spool_dir=settings.ZEEK_SPOOL_DIR,
                queue=queue,
                file_pattern=settings.ZEEK_SPOOL_FILE_PATTERN,
                poll_interval_sec=settings.ZEEK_SPOOL_POLL_INTERVAL_SEC,
                initial_offsets=initial_offsets,
            )

            worker = IngestionWorker(
                queue=queue,
                session_maker=session_maker,
                offset_tracker=offset_tracker,
                broadcaster=broadcaster,
                tailer=tailer,
                batch_size=settings.ZEEK_BATCH_SIZE,
                flush_interval_sec=settings.ZEEK_BATCH_FLUSH_INTERVAL_SEC,
                dedup_cache_size=settings.ZEEK_DEDUP_CACHE_SIZE,
            )

            # Store context on app state for API route access
            app.state.zeek_ingestion = {
                "tailer": tailer,
                "worker": worker,
                "broadcaster": broadcaster,
                "queue": queue,
                "start_time": time.time(),
                "heartbeat_sec": settings.ZEEK_SSE_HEARTBEAT_SEC,
            }

            # Launch background tasks
            tailer_task = asyncio.create_task(tailer.run(), name="zeek-tailer")
            worker_task = asyncio.create_task(worker.run(), name="zeek-worker")
            ingestion_tasks = [tailer_task, worker_task]

            logger.info(
                "Zeek real-time ingestion started: spool=%s, queue=%d, batch=%d",
                settings.ZEEK_SPOOL_DIR,
                settings.ZEEK_QUEUE_MAX_SIZE,
                settings.ZEEK_BATCH_SIZE,
            )
        except Exception as e:
            logger.error("Failed to start Zeek ingestion pipeline: %s", e)
    elif settings.ZEEK_SPOOL_ENABLED and not db_status.get("connected"):
        logger.warning(
            "ZEEK_SPOOL_ENABLED=true but database unavailable — "
            "real-time ingestion not started."
        )

    yield

    # Shutdown
    logger.info("Shutting down AI Network Anomaly Detection Platform...")

    if ingestion_tasks:
        import asyncio

        ctx = getattr(app.state, "zeek_ingestion", {})
        tailer = ctx.get("tailer")
        worker = ctx.get("worker")

        # 1. Stop the tailer (no new reads)
        if tailer:
            tailer.request_stop()

        # 2. Signal worker to drain queue and persist remaining records
        if worker:
            await worker.drain_and_stop()

        # 3. Wait for tasks to finish (with timeout)
        done, pending = await asyncio.wait(
            ingestion_tasks, timeout=15.0,
        )
        for t in pending:
            logger.warning("Force-cancelling ingestion task: %s", t.get_name())
            t.cancel()
        if pending:
            await asyncio.wait(pending, timeout=5.0)

        logger.info("Zeek ingestion pipeline shut down.")


app = FastAPI(
    title="AI Network Anomaly Detection Platform",
    version="1.0.0",
    description=(
        "Production-oriented ML inference service for defensive network flow analysis. "
        "Integrates supervised multi-class attack detection (XGBoost, Random Forest, Logistic Regression) "
        "with statistical anomaly detection (Isolation Forest), hybrid risk-decision triage, and persistent PostgreSQL telemetry."
    ),
    lifespan=lifespan,
)

# Security Headers middleware (defensive response headers, conditional HSTS)
app.add_middleware(SecurityHeadersMiddleware)

# CORS middleware for frontend dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(FeatureValidationError)
async def feature_validation_exception_handler(
    request: Request, exc: FeatureValidationError
) -> JSONResponse:
    """Map domain feature validation errors to structured HTTP 422 responses."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "FeatureValidationError",
            "message": str(exc),
            "missing_features": exc.missing_features,
            "invalid_fields": exc.invalid_fields,
        },
    )


# Root health probe (Public)
app.include_router(health_router)

# Register API routers under /api/v1 prefix
# Public endpoints
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")

# Authenticated application endpoints (guarded by session cookie)
app.include_router(metrics_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(decisions_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(inference_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(models_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(pcap_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(zeek_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(zeek_stream_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(telemetry_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(alerts_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
