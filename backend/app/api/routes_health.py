"""Health and System Status API routes for Hardened Capstone Deployment."""

from typing import Any
from fastapi import APIRouter, Response, status
from app.core.config import settings
from app.core.database import check_database_connection
from app.services.model_registry import get_model_registry

router = APIRouter(tags=["health"])


@router.get("/health")
@router.get("/health/live")
async def health_liveness() -> dict[str, str]:
    """Minimal liveness probe for process heartbeat."""
    return {
        "status": "ok",
        "service": "network-anomaly-api",
    }


@router.get("/health/ready")
async def health_readiness(response: Response) -> dict[str, Any]:
    """Guarded readiness probe verifying database connectivity and model availability."""
    db_status = await check_database_connection()
    db_ok = db_status.get("connected", False)

    registry = get_model_registry()
    try:
        # Verify required production models are loadable
        sup = registry.get_default_supervised_model()
        anom = registry.get_default_anomaly_model()
        models_ok = sup is not None and anom is not None
    except Exception:
        models_ok = False

    is_ready = (db_ok or not settings.DATABASE_REQUIRED) and models_ok

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "not_ready",
        "database": "connected" if db_ok else "disconnected",
        "models": "loaded" if models_ok else "unavailable",
        "environment": settings.ENVIRONMENT,
    }

