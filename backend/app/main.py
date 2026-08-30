"""FastAPI Application Entrypoint for AI Network Anomaly Detection Platform."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes_decisions import router as decisions_router
from app.api.routes_health import router as health_router
from app.api.routes_inference import router as inference_router
from app.api.routes_models import router as models_router
from app.api.routes_pcap import router as pcap_router
from app.services.model_registry import get_model_registry
from app.services.preprocessor import FeatureValidationError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("backend.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown lifespan context."""
    logger.info("Initializing AI Network Anomaly Detection Platform...")
    registry = get_model_registry()
    try:
        sup = registry.get_default_supervised_model()
        anom = registry.get_default_anomaly_model()
        logger.info(
            f"Preloaded default models: Supervised='{sup.key}', Anomaly='{anom.key}'"
        )
    except Exception as e:
        logger.warning(f"Could not preload default models on startup: {e}")
    yield
    logger.info("Shutting down AI Network Anomaly Detection Platform...")


app = FastAPI(
    title="AI Network Anomaly Detection Platform",
    version="1.0.0",
    description=(
        "Production-oriented ML inference service for defensive network flow analysis. "
        "Integrates supervised multi-class attack detection (XGBoost, Random Forest, Logistic Regression) "
        "with statistical anomaly detection (Isolation Forest) and hybrid risk-decision triage."
    ),
    lifespan=lifespan,
)

# CORS middleware for frontend dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


# Register API routers under /api/v1 prefix
app.include_router(health_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(inference_router, prefix="/api/v1")
app.include_router(models_router, prefix="/api/v1")
app.include_router(pcap_router, prefix="/api/v1")

